#define _DEFAULT_SOURCE

#include <sys/mman.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include <time.h>

#include "array.h"
#include "gc.h"
#include "hawk.h"
#include "log.h"
#include "profiler.h"
#include "types.h"
#include "util/list.h"
#include "util/stack.h"

#define LOG_OBJ_HEADER UINT64_MAX

typedef struct {
  uint64_t offset;
  uint64_t val;
} log_item;
static log_item *log_buf;

enum : size_t {
  BLOCK_SIZE = 262144,
  BLOCK_MARK_BYTES = BLOCK_SIZE / 64,
  BLOCK_OVERHEAD = sizeof(uint32_t) + 2 + BLOCK_MARK_BYTES,
  BLOCK_DATA_SIZE = BLOCK_SIZE - BLOCK_OVERHEAD,
  GC_COLLECT_AFTER = 32 * 1024 * 1024,
};

enum { BLOCK_FREE, BLOCK_USED };

typedef struct gc_block {
  _Atomic uint32_t live_objects;
  uint8_t satb_marked;
  uint8_t state;
  uint8_t marks[BLOCK_MARK_BYTES];
  uint8_t data[BLOCK_DATA_SIZE];
} gc_block;

uintptr_t gc_hp;
uintptr_t gc_hp_end;
gc_root_range gc_roots[GC_MAX_ROOTS];
size_t gc_roots_len;

static void *gc_base;
static void *gc_mmap_base;
static size_t gc_mmap_size;
size_t gc_size;
static uintptr_t gc_base_cur;
static gc_block **free_blocks;
static gc_scan_callback scan_callback;
static void *scan_data;
uint64_t total_gc_cnt;
static LIST_HEAD(large_allocs);
static gc_block **all_blocks;
static gc_block **nursery_blocks;
static gc_header **large_nursery;
static size_t collect_after;
static size_t next_collect;
static gc_obj *bcfunc_list;
static gc_obj *bcfunc_roots;
static bool bcfunc_list_unsorted;
static mtx_t free_blocks_lock;
static mtx_t large_allocs_lock;
static mtx_t decrement_lock;
static cnd_t decrement_cond;

STACK(gc_field_stack, gc_obj *)
STACK(gc_obj_stack, gc_obj)
STACK(gc_obj_stack_stack, gc_obj_stack)

static inline void gc_field_stack_reserve(gc_field_stack *s, size_t n) {
  assert(n <= SIZE_MAX - s->len);
  while (s->len + n > s->cap) {
    s->data = stack_grow(s->data, sizeof(gc_obj *), &s->cap);
  }
}

static inline void gc_field_stack_push_unchecked(gc_field_stack *s, gc_obj *v) {
  s->data[s->len++] = v;
}

static inline void inc_reserve_fields(void *ctx, size_t n) {
  gc_field_stack_reserve(ctx, n);
}

static gc_field_stack cur_increments;
static gc_obj_stack cur_decrements;
static gc_obj_stack next_decrements;
static gc_obj_stack_stack decrement_batches;
static gc_obj_stack satb_stack;
static thrd_t decrement_thread;
static bool decrement_thread_started;
static bool decrement_busy;
static bool decrement_stop;

struct large_alloc {
  list_head list;
  uint8_t satb_marked;
};

_Static_assert(sizeof(gc_block) <= BLOCK_SIZE);

static inline gc_block *object_block(gc_header *hdr) {
  return (gc_block *)((uintptr_t)hdr & ~(uintptr_t)(BLOCK_SIZE - 1));
}

static void block_mark_all(gc_block *block) {
  memset(block->marks, 0xff, sizeof(block->marks));
  block->satb_marked = 1;
}

static void block_mark_clear(gc_block *block) {
  memset(block->marks, 0, sizeof(block->marks));
  block->satb_marked = 0;
}

static bool mark_small_object(gc_header *hdr) {
  gc_block *block = object_block(hdr);
  uintptr_t off = (uintptr_t)hdr - (uintptr_t)block->data;
  size_t bit = off / sizeof(gc_obj);
  size_t idx = bit / 8;
  uint8_t mask = (uint8_t)(1u << (bit % 8));
  bool marked = block->marks[idx] & mask;
  block->marks[idx] |= mask;
  block->satb_marked = 1;
  return marked;
}

static bool mark_large_object(gc_header *hdr) {
  struct large_alloc *la = (struct large_alloc *)hdr - 1;
  bool marked = la->satb_marked;
  la->satb_marked = 1;
  return marked;
}

static void clear_all_marks(void) {
  for (size_t i = 0; i < arrlen(all_blocks); i++) {
    block_mark_clear(all_blocks[i]);
  }
  list_head *pos;
  list_for_each(pos, &large_allocs) {
    struct large_alloc *la = container_of(pos, struct large_alloc, list);
    la->satb_marked = 0;
  }
}

static bool satb_enabled = false;
static bool satb_active;
static size_t satb_waste_threshold = 20;
static size_t satb_pred_live_blocks = 64;
static const char *satb_start_reason;

static size_t mature_block_count(void) {
  return arrlen(all_blocks) - arrlen(free_blocks) - arrlen(nursery_blocks);
}

static bool satb_should_start(void) {
  if (!satb_enabled || satb_active) {
    return false;
  }
  if (satb_waste_threshold == 0) {
    satb_start_reason = "forced";
    return true;
  }
  size_t mature = mature_block_count();
  if (mature > satb_pred_live_blocks) {
    size_t waste = mature - satb_pred_live_blocks;
    size_t threshold = arrlen(all_blocks) * satb_waste_threshold / 100;
    if (waste >= threshold) {
      satb_start_reason = "waste";
      return true;
    }
  }
  return false;
}

static void satb_update_prediction(size_t observed) {
  if (observed > satb_pred_live_blocks) {
    satb_pred_live_blocks = observed;
  } else {
    satb_pred_live_blocks = (observed + 3 * satb_pred_live_blocks) / 4;
  }
}

static void satb_push(gc_obj v) {
  if (is_heap_object(v)) {
    gc_obj_stack_push(&satb_stack, v);
  }
}

static void satb_add_root(const uint64_t *rootp, size_t len) {
  uint64_t *slots = (uint64_t *)rootp;
  for (size_t i = 0; i < len; i++) {
    satb_push((gc_obj){.value = (int64_t)slots[i]});
  }
}

INLINE inline static bool visit_root(gc_obj *root, gc_field_stack *increments);
static int decrement_thread_main(void *arg);
static void wait_for_decrements(void);

static void satb_push_roots(void) {
  for (size_t i = 0; i < gc_roots_len; i++) {
    gc_root_range root = gc_roots[i];
    if (root.tag != 0) {
      uintptr_t *slots = (uintptr_t *)root.ptr;
      for (size_t j = 0; j < root.len; j++) {
        if (slots[j] == 0)
          continue;
        satb_push(tag_header((gc_header *)slots[j], root.tag));
      }
    } else {
      uint64_t *base = (uint64_t *)root.ptr;
      for (size_t j = 0; j < root.len; j++) {
        satb_push((gc_obj){.value = (int64_t)base[j]});
      }
    }
  }
  for (size_t i = 0; i < arrlen(bcfunc_roots); i++) {
    satb_push(bcfunc_roots[i]);
  }
  if (scan_callback) {
    scan_callback(scan_data, satb_add_root);
  }
}

void gc_init(void) {
  char *env = getenv("GC_SPACE");
  size_t mb = env ? atol(env) : 2048;
  gc_size = mb * 1024 * 1024;
  env = getenv("GC_COLLECT");
  collect_after = env ? (size_t)atol(env) * 1024 * 1024 : GC_COLLECT_AFTER;
  next_collect = collect_after;
  mtx_init(&free_blocks_lock, mtx_plain);
  mtx_init(&large_allocs_lock, mtx_plain);
  mtx_init(&decrement_lock, mtx_plain);
  cnd_init(&decrement_cond);
  decrement_thread_started =
      thrd_create(&decrement_thread, decrement_thread_main, nullptr) ==
      thrd_success;
  env = getenv("GC_SATB");
  if (env && strcmp(env, "0") == 0) {
    satb_enabled = false;
  }
  env = getenv("GC_SATB_WASTE");
  if (env) {
    satb_enabled = true;
    satb_waste_threshold = (size_t)atol(env);
  }
  satb_enabled = false;
  gc_mmap_size = gc_size + BLOCK_SIZE;
  gc_mmap_base = mmap(nullptr, gc_mmap_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
  if (gc_mmap_base == MAP_FAILED) {
    perror("mmap gc space");
    abort();
  }
  LOG(gc, "GC_SPACE: %zu MB", mb);
  uintptr_t base =
      ((uintptr_t)gc_mmap_base + BLOCK_SIZE - 1) & ~(uintptr_t)(BLOCK_SIZE - 1);
  gc_base = (void *)base;
  gc_base_cur = (uintptr_t)gc_base;
  gc_hp_end = (uintptr_t)gc_base;
  gc_hp = gc_hp_end;
}

static gc_block *block_alloc_raw(void) {
  gc_block *block;
  mtx_lock(&free_blocks_lock);
  if (arrlen(free_blocks) > 0) {
    block = arrpop_last(free_blocks);
    mtx_unlock(&free_blocks_lock);
    block->state = BLOCK_USED;
  } else {
    mtx_unlock(&free_blocks_lock);
    if (gc_base_cur + BLOCK_SIZE > (uintptr_t)gc_base + gc_size) {
      fprintf(stderr, "block_alloc: out of GC space\n");
      abort();
    }
    block = (gc_block *)gc_base_cur;
    gc_base_cur += BLOCK_SIZE;
    block->state = BLOCK_USED;
    arrput(all_blocks, block);
  }
  return block;
}

static gc_block *block_alloc(void) {
  if (next_collect < BLOCK_SIZE) {
    gc_collect();
  }
  next_collect -= BLOCK_SIZE;
  gc_block *block = block_alloc_raw();
  if (unlikely(satb_active)) {
    block_mark_all(block);
  }
  arrput(nursery_blocks, block);
  return block;
}

static void block_free(gc_block *block) {
  block->state = BLOCK_FREE;
  atomic_store_explicit(&block->live_objects, 0, memory_order_relaxed);
  mtx_lock(&free_blocks_lock);
  arrput(free_blocks, block);
  mtx_unlock(&free_blocks_lock);
}

static size_t free_block_count(void) {
  mtx_lock(&free_blocks_lock);
  size_t len = arrlen(free_blocks);
  mtx_unlock(&free_blocks_lock);
  return len;
}

static inline bool is_large_alloc(gc_header *hdr) {
  return hdr->flags & GC_LARGE;
}

static void satb_trace_field(gc_obj *field, void *ctx) {
  gc_obj v = *field;
  if (is_heap_object(v)) {
    gc_obj_stack_push((gc_obj_stack *)ctx, v);
  }
}

static void satb_process(gc_obj obj) {
  if (!is_heap_object(obj)) {
    return;
  }
  gc_header *hdr = to_gc_header(obj);
  if (is_large_alloc(hdr)) {
    if (mark_large_object(hdr)) {
      return;
    }
  } else {
    if (mark_small_object(hdr)) {
      return;
    }
  }
  trace_heap_object(hdr, hdr->type, satb_trace_field, &satb_stack);
}

enum { SATB_PROCESS_BATCH = 1000000 };

static void satb_process_some(void) {
  for (size_t i = 0; i < SATB_PROCESS_BATCH && satb_stack.len; i++) {
    satb_process(gc_obj_stack_pop(&satb_stack));
  }
}

static void satb_sweep(void) {
  size_t live = 0, freed_blocks = 0, freed_large = 0;
  for (size_t i = 0; i < arrlen(all_blocks); i++) {
    gc_block *block = all_blocks[i];
    // Note nursury may have already freed.
    if (block->satb_marked) {
      live++;
    } else if (block->state != BLOCK_FREE) {
      block_free(block);
      freed_blocks++;
    }
  }
  list_head *pos = large_allocs.next;
  while (pos != &large_allocs) {
    struct large_alloc *la = container_of(pos, struct large_alloc, list);
    pos = pos->next;
    if (la->satb_marked) {
      la->satb_marked = 0;
    } else {
      list_del(&la->list);
      free(la);
      freed_large++;
    }
  }
  satb_update_prediction(live);
  LOG(gc, "satb finish: %zu blocks freed, %zu large freed", freed_blocks,
      freed_large);
}

static void mark_object_block(gc_header *hdr) {
  if (is_large_alloc(hdr)) {
    return;
  }
  gc_block *block = (gc_block *)((uintptr_t)hdr & ~(uintptr_t)(BLOCK_SIZE - 1));
  atomic_fetch_add_explicit(&block->live_objects, 1, memory_order_relaxed);
}

static void clear_object_block(gc_header *hdr) {
  gc_block *block = (gc_block *)((uintptr_t)hdr & ~(uintptr_t)(BLOCK_SIZE - 1));
  uint32_t old =
      atomic_fetch_sub_explicit(&block->live_objects, 1, memory_order_relaxed);
  assert(old > 0);
  if (old == 1) {
    block_free(block);
  }
}

void gc_free(void) {
  wait_for_decrements();
  if (decrement_thread_started) {
    mtx_lock(&decrement_lock);
    decrement_stop = true;
    cnd_signal(&decrement_cond);
    mtx_unlock(&decrement_lock);
    thrd_join(decrement_thread, nullptr);
    decrement_thread_started = false;
  }
  if (gc_mmap_base && gc_mmap_base != MAP_FAILED) {
    munmap(gc_mmap_base, gc_mmap_size);
  }
  arrfree(all_blocks);
  arrfree(nursery_blocks);
  arrfree(large_nursery);
  arrfree(bcfunc_list);
  arrfree(bcfunc_roots);
  arrfree(free_blocks);
  arrfree(log_buf);
  free(cur_increments.data);
  free(cur_decrements.data);
  free(next_decrements.data);
  free(satb_stack.data);
  while (!list_empty(&large_allocs)) {
    list_head *pos = large_allocs.next;
    list_del(pos);
    free(container_of(pos, struct large_alloc, list));
  }
  cnd_destroy(&decrement_cond);
  mtx_destroy(&decrement_lock);
  mtx_destroy(&large_allocs_lock);
  mtx_destroy(&free_blocks_lock);
}

static int cmp_bcfunc(const void *ap, const void *bp) {
  uintptr_t a = (uintptr_t)to_raw_ptr(*(const gc_obj *)ap);
  uintptr_t b = (uintptr_t)to_raw_ptr(*(const gc_obj *)bp);
  return (a > b) - (a < b);
}

static int cmp_bcfunc_range(const void *kp, const void *ep) {
  uintptr_t p = *(const uintptr_t *)kp;
  bcfunc *func = (bcfunc *)to_raw_ptr(*(const gc_obj *)ep);
  uintptr_t base = (uintptr_t)func;
  if (p < base) {
    return -1;
  }
  size_t sz = heap_object_size(func);
  if (p >= base + sz) {
    return 1;
  }
  return 0;
}

void gc_register_bcfunc(bcfunc *func) {
  gc_obj tagged = tag_func(func);
  arrput(bcfunc_list, tagged);
  arrput(bcfunc_roots, tagged);
  bcfunc_list_unsorted = true;
}

void gc_set_scan_callback(gc_scan_callback cb, void *data) {
  scan_callback = cb;
  scan_data = data;
}

void *gc_base_ptr(void *p) {
  if (arrlen(bcfunc_list) == 0) {
    return nullptr;
  }
  if (bcfunc_list_unsorted) {
    qsort(bcfunc_list, arrlen(bcfunc_list), sizeof(gc_obj), cmp_bcfunc);
    bcfunc_list_unsorted = false;
  }
  gc_obj *result = bsearch(&p, bcfunc_list, arrlen(bcfunc_list), sizeof(gc_obj),
                           cmp_bcfunc_range);
  return result ? to_raw_ptr(*result) : nullptr;
}

static void snapshot_field(gc_obj *field, void *ctx) {
  gc_obj v = *field;
  if (!is_heap_object(v)) {
    return;
  }
  uintptr_t base = (uintptr_t)ctx;
  arrput(log_buf, ((log_item){(uintptr_t)field - base, v.value}));
}

NOINLINE void gc_log_slow(gc_obj obj) {
  gc_header *hdr = to_gc_header(obj);
  if (atomic_load_explicit(&hdr->rc, memory_order_relaxed) == 0) {
    return;
  }
  if (hdr->flags & GC_LOGGED) {
    return;
  }
  hdr->flags |= GC_LOGGED;
  arrput(log_buf, ((log_item){LOG_OBJ_HEADER, (uint64_t)hdr}));
  trace_heap_object(hdr, hdr->type, snapshot_field, hdr);
}

static void *gc_large_alloc(uint64_t sz);

static inline bool is_large_size(uint64_t sz) { return sz >= BLOCK_SIZE / 2; }

NOINLINE void *gc_alloc_slow(uint64_t sz) {
  assert((sz & 0x7) == 0);
  uintptr_t new_hp = gc_hp - sz;
  if (likely(new_hp >= gc_hp_end)) {
    gc_hp = new_hp;
    *(uint64_t *)gc_hp = 0;
    return (void *)gc_hp;
  }

  if (is_large_size(sz)) {
    return gc_large_alloc(sz);
  }

  gc_block *block = block_alloc();
  gc_hp_end = (uintptr_t)block->data;
  gc_hp = (uintptr_t)block->data + BLOCK_DATA_SIZE;
  MUSTTAIL return gc_alloc_slow(sz);
}

static void *gc_large_alloc(uint64_t sz) {
  if (next_collect < sz) {
    next_collect = -1;
    gc_collect();
  }
  next_collect -= sz;
  struct large_alloc *la = malloc(sizeof(*la) + sz);
  if (!la) {
    fprintf(stderr, "gc_large_alloc: out of memory\n");
    abort();
  }
  init_list_head(&la->list);
  mtx_lock(&large_allocs_lock);
  list_add_tail(&la->list, &large_allocs);
  mtx_unlock(&large_allocs_lock);
  arrput(large_nursery, (gc_header *)(la + 1));
  *(uint64_t *)(la + 1) = 0;
  ((gc_header *)(la + 1))->flags |= GC_LARGE;
  if (unlikely(satb_active)) {
    la->satb_marked = 1;
  }
  return la + 1;
}

static uintptr_t copy_hp;
static uintptr_t copy_hp_end;
static size_t copy_alloc_bytes;

INLINE inline static gc_header *copy_alloc(uint64_t sz) {
  assert((sz & 0x7) == 0);
  copy_alloc_bytes += sz;
  assert(!is_large_size(sz));
  uintptr_t new_hp = copy_hp - sz;
  if (copy_hp == 0 || new_hp < copy_hp_end) {
    gc_block *block = block_alloc_raw();
    assert(block);
    if (unlikely(satb_active)) {
      block_mark_all(block);
    }
    copy_hp_end = (uintptr_t)block->data;
    copy_hp = (uintptr_t)block->data + BLOCK_DATA_SIZE;
    new_hp = copy_hp - sz;
    assert(new_hp >= copy_hp_end);
  }
  copy_hp = new_hp;
  return (gc_header *)copy_hp;
}

INLINE inline static bool inc_visit_heap(gc_obj *field,
                                         gc_field_stack *increments);

INLINE inline static bool visit_root(gc_obj *root, gc_field_stack *increments) {
  if (!is_heap_object(*root)) {
    return false;
  }
  bool changed = inc_visit_heap(root, increments);
  gc_obj_stack_push(&next_decrements, *root);
  return changed;
}

INLINE inline static void inc_trace_field(gc_obj *field, void *ctx) {
  if (is_heap_object(*field)) {
    gc_field_stack_push_unchecked(ctx, field);
  }
}

INLINE inline static bool inc_visit_heap(gc_obj *field,
                                         gc_field_stack *increments) {
  gc_obj obj = *field;
  gc_header *hdr = to_gc_header(obj);
  if (atomic_load_explicit(&hdr->rc, memory_order_relaxed) != 0) {
    atomic_fetch_add_explicit(&hdr->rc, 1, memory_order_relaxed);
    return false;
  }

  // rc == 0: object may need copying. Check forwarding first in case
  // another field already copied it.
  uint8_t tag = get_tag(obj);
  if (is_forwarded(hdr)) {
    hdr = forward_ptr(hdr);
    *field = tag_header(hdr, tag);
    atomic_fetch_add_explicit(&hdr->rc, 1, memory_order_relaxed);
    return true;
  }

  bool changed = false;
  if (hdr->type != FUNC_TAG && !is_large_alloc(hdr)) {
    size_t sz = heap_align(heap_object_size(hdr));
    gc_header *copy = copy_alloc(sz);
    uint64_t *d = (uint64_t *)copy, *s = (uint64_t *)hdr;
    size_t n = sz / 8;
    switch (n) {
    case 3:
      d[2] = s[2];
    case 2:
      d[1] = s[1];
    case 1:
      d[0] = s[0];
      break;
    default:
      for (size_t i = 0; i < n; i++)
        d[i] = s[i];
      break;
    }
    copy->flags &= (uint8_t)~(GC_LOGGED | GC_FWD_TAG);
    atomic_store_explicit(&copy->rc, 0, memory_order_relaxed);
    set_forward(hdr, copy);
    hdr = copy;
    *field = tag_header(hdr, tag);
    changed = true;
  }
  atomic_store_explicit(&hdr->rc, 1, memory_order_relaxed);
  mark_object_block(hdr);
  trace_heap_object_reserved(hdr, hdr->type, inc_reserve_fields,
                             inc_trace_field, increments);
  return changed;
}

INLINE inline static void process_increments(gc_field_stack *increments) {
  while (increments->len) {
    gc_obj *field = gc_field_stack_pop(increments);
    (void)inc_visit_heap(field, increments);
  }
}

INLINE inline static void dec_trace_field(gc_obj *field, void *ctx) {
  gc_obj obj = *field;
  if (is_heap_object(obj)) {
    gc_obj_stack_push(ctx, obj);
  }
}

INLINE inline static void process_decrements(gc_obj_stack *decrements) {
  while (decrements->len) {
    gc_obj obj = gc_obj_stack_pop(decrements);
    gc_header *hdr = to_gc_header(obj);
    // Deferred duplicate decrements can target an object already reclaimed or
    // forwarded by an earlier decrement in this batch.
    if (atomic_load_explicit(&hdr->rc, memory_order_relaxed) == 0) {
      continue;
    }
    uint32_t old =
        atomic_fetch_sub_explicit(&hdr->rc, 1, memory_order_relaxed);
    assert(old > 0);
    if (old > 1) {
      continue;
    }

    if (unlikely(satb_active)) {
      satb_process(obj);
    }
    trace_heap_object(hdr, hdr->type, dec_trace_field, decrements);
    if (is_large_alloc(hdr)) {
      struct large_alloc *la = (struct large_alloc *)hdr - 1;
      mtx_lock(&large_allocs_lock);
      list_del(&la->list);
      mtx_unlock(&large_allocs_lock);
      free(la);
    } else {
      clear_object_block(hdr);
    }
  }
}

static int decrement_thread_main(void *arg) {
  (void)arg;
  mtx_lock(&decrement_lock);
  for (;;) {
    while (decrement_batches.len == 0 && !decrement_stop) {
      cnd_wait(&decrement_cond, &decrement_lock);
    }
    if (decrement_stop && decrement_batches.len == 0) {
      break;
    }
    gc_obj_stack batch = gc_obj_stack_stack_pop(&decrement_batches);
    decrement_busy = true;
    mtx_unlock(&decrement_lock);
    process_decrements(&batch);
    free(batch.data);
    mtx_lock(&decrement_lock);
    decrement_busy = false;
    cnd_broadcast(&decrement_cond);
  }
  mtx_unlock(&decrement_lock);
  return 0;
}

static void wait_for_decrements(void) {
  if (!decrement_thread_started) {
    return;
  }
  mtx_lock(&decrement_lock);
  while (decrement_busy || decrement_batches.len != 0) {
    cnd_wait(&decrement_cond, &decrement_lock);
  }
  mtx_unlock(&decrement_lock);
}

static void start_decrements(void) {
  if (cur_decrements.len == 0) {
    return;
  }
  if (!decrement_thread_started) {
    process_decrements(&cur_decrements);
    return;
  }
  mtx_lock(&decrement_lock);
  gc_obj_stack_stack_push(&decrement_batches, cur_decrements);
  cur_decrements = (gc_obj_stack){0};
  cnd_signal(&decrement_cond);
  mtx_unlock(&decrement_lock);
}

static void gc_add_mark_root(const uint64_t *rootp, size_t len) {
  gc_field_stack *increments = &cur_increments;
  uint64_t *slots = (uint64_t *)rootp;
  for (size_t i = 0; i < len; i++) {
    gc_obj v = {.value = (int64_t)slots[i]};
    if (visit_root(&v, increments)) {
      slots[i] = (uint64_t)v.value;
    }
  }
}

static inline double elapsed_ms(struct timespec s, struct timespec e) {
  return ((double)(e.tv_sec - s.tv_sec) * 1000.0) +
         ((double)(e.tv_nsec - s.tv_nsec) / 1000000.0);
}

void gc_collect(void) {
  total_gc_cnt++;

  {
    auto tmp = cur_decrements;
    cur_decrements = next_decrements;
    next_decrements = tmp;
    next_decrements.len = 0;
  }

  static struct timespec prev_gc_end;
  struct timespec t0;
  struct timespec t1;
  struct timespec t2;
  struct timespec t3;
  struct timespec t_satb;
  struct timespec t_satb_end;
  struct timespec t4;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  double mutator_ms = prev_gc_end.tv_sec ? elapsed_ms(prev_gc_end, t0) : 0.0;
  size_t free_before = free_block_count();
  profiler_set_in_gc(true);
  auto buflen = arrlen(log_buf);
  copy_hp = 0;
  copy_hp_end = 0;
  gc_field_stack *increments = &cur_increments;

  // 1) walk roots — eagerly drain increments after each batch so
  //    cur_increments never grows large, matching old per-root visit()
  //    behavior.
  for (size_t i = 0; i < gc_roots_len; i++) {
    gc_root_range root = gc_roots[i];
    if (root.tag != 0) {
      uintptr_t *slots = (uintptr_t *)root.ptr;
      for (size_t j = 0; j < root.len; j++) {
        if (slots[j] == 0) {
          continue;
        }
        gc_obj v = tag_header((gc_header *)slots[j], root.tag);
        if (visit_root(&v, increments)) {
          slots[j] = (uintptr_t)to_raw_ptr(v);
        }
      }
    } else {
      uint64_t *base = (uint64_t *)root.ptr;
      for (size_t j = 0; j < root.len; j++) {
        gc_obj v = {.value = (int64_t)base[j]};
        if (visit_root(&v, increments)) {
          base[j] = (uint64_t)v.value;
        }
      }
    }
    process_increments(increments);
  }

  for (size_t i = 0; i < arrlen(bcfunc_roots); i++) {
    gc_field_stack_push(increments, &bcfunc_roots[i]);
  }
  arrlen_set(bcfunc_roots, 0);
  process_increments(increments);

  if (scan_callback) {
    scan_callback(scan_data, gc_add_mark_root);
  }
  process_increments(increments);

  // Handle write barrier log
  for (size_t i = 0; i < arrlen(log_buf);) {
    log_item cur = log_buf[i];
    assert(cur.offset == LOG_OBJ_HEADER);
    void *obj = (void *)cur.val;
    ((gc_header *)obj)->flags &= (uint8_t)~GC_LOGGED;
    assert(atomic_load_explicit(&((gc_header *)obj)->rc,
                                memory_order_relaxed) != 0);

    trace_heap_object_reserved((gc_header *)obj, ((gc_header *)obj)->type,
                               inc_reserve_fields, inc_trace_field,
                               increments);

    i++;
    if (i >= arrlen(log_buf)) {
      break;
    }
    cur = log_buf[i];
    while (cur.offset != LOG_OBJ_HEADER) {
      gc_obj old_val = {.value = (int64_t)cur.val};
      if (is_heap_object(old_val) &&
          atomic_load_explicit(&to_gc_header(old_val)->rc,
                               memory_order_relaxed) != 0) {
        gc_obj_stack_push(&cur_decrements, old_val);
        if (unlikely(satb_active)) {
          satb_push(old_val);
        }
      }
      i++;
      if (i >= arrlen(log_buf)) {
        break;
      }
      cur = log_buf[i];
    }
    process_increments(increments);
  }
  arrlen_set(log_buf, 0);
  clock_gettime(CLOCK_MONOTONIC, &t1);

  // 2) Drain any remaining increments
  process_increments(increments);
  clock_gettime(CLOCK_MONOTONIC, &t2);

  // 3) Decrements are queued to a background thread after nursery sweep.
  clock_gettime(CLOCK_MONOTONIC, &t3);

  // 4) Sweep nursery: free empty blocks and dead large allocs,
  //    leave live ones for decrements
  for (size_t i = 0; i < arrlen(nursery_blocks); i++) {
    if (atomic_load_explicit(&nursery_blocks[i]->live_objects,
                             memory_order_relaxed) == 0) {
      block_free(nursery_blocks[i]);
    }
  }
  arrlen_set(nursery_blocks, 0);

  for (size_t i = 0; i < arrlen(large_nursery); i++) {
    gc_header *hdr = large_nursery[i];
    if (atomic_load_explicit(&hdr->rc, memory_order_relaxed) == 0) {
      struct large_alloc *la = (struct large_alloc *)hdr - 1;
      mtx_lock(&large_allocs_lock);
      list_del(&la->list);
      mtx_unlock(&large_allocs_lock);
      free(la);
    }
  }
  arrlen_set(large_nursery, 0);
  start_decrements();

  clock_gettime(CLOCK_MONOTONIC, &t_satb);

  if (unlikely(satb_active)) {
    satb_process_some();
    LOG(gc, "satb queue: %zu", satb_stack.len);
    // Must check for finish *after* the write log is processed:
    // we HAVE to process current write log before SATB can be done.
    if (satb_stack.len == 0) {
      // Must sweep satb *after* nursury.
      // nursury doesn't check for double-free of blocks
      // currently.
      satb_sweep();
      satb_active = false;
    }
  }
  clock_gettime(CLOCK_MONOTONIC, &t_satb_end);

  // MUST start satb *before* allocing a new block,
  // so new blocks start marked.
  if (satb_should_start()) {
    LOG(gc, "satb start: %s", satb_start_reason);
    clear_all_marks();
    satb_stack.len = 0;
    satb_push_roots();
    satb_active = true;
  }

  next_collect = collect_after;

  // 5) Get a fresh block for allocation
  gc_block *fresh = block_alloc();
  gc_hp_end = (uintptr_t)fresh->data;
  gc_hp = (uintptr_t)fresh->data + BLOCK_DATA_SIZE;
  clock_gettime(CLOCK_MONOTONIC, &t4);

  size_t freed_mb =
      (free_block_count() - free_before) * BLOCK_SIZE / (size_t)(1024 * 1024);
  size_t nursery_mb = copy_alloc_bytes / (size_t)(1024 * 1024);
  copy_alloc_bytes = 0;
  LOG(gc,
      "gc_collect: %.3f/+%.3f ms (roots %.3f, dec %.3f, sweep %.3f, "
      "satb %.3f), "
      "blocks: %zu total, %zu free (+%zu MB), nursery copy: %zu MB, "
      "buflen %li",
      elapsed_ms(t0, t4), mutator_ms, elapsed_ms(t0, t1), elapsed_ms(t2, t3),
      elapsed_ms(t3, t_satb), elapsed_ms(t_satb, t_satb_end),
      arrlen(all_blocks), free_block_count(), freed_mb, nursery_mb, buflen);
  prev_gc_end = t4;
  profiler_set_in_gc(false);
}

EXPORT uint64_t SCM_GC_CNT(void) { return total_gc_cnt; }
