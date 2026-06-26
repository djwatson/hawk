#define _DEFAULT_SOURCE

#include <sys/mman.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
  BLOCK_DATA_SIZE = BLOCK_SIZE - sizeof(uint32_t),
  GC_COLLECT_AFTER = 32 * 1024 * 1024,
};

typedef struct gc_block {
  uint32_t live_objects;
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

STACK(gc_field_stack, gc_obj *)
STACK(gc_obj_stack, gc_obj)

static gc_field_stack cur_increments;
static gc_obj_stack cur_decrements;
static gc_obj_stack next_decrements;

struct large_alloc {
  list_head list;
};

_Static_assert(sizeof(gc_block) <= BLOCK_SIZE);

void gc_init(void) {
  char *env = getenv("GC_SPACE");
  size_t mb = env ? atol(env) : 2048;
  gc_size = mb * 1024 * 1024;
  env = getenv("GC_COLLECT");
  collect_after = env ? (size_t)atol(env) * 1024 * 1024 : GC_COLLECT_AFTER;
  next_collect = collect_after;
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
  if (arrlen(free_blocks) > 0) {
    block = arrpop_last(free_blocks);
  } else {
    if (gc_base_cur + BLOCK_SIZE > (uintptr_t)gc_base + gc_size) {
      fprintf(stderr, "block_alloc: out of GC space\n");
      abort();
    }
    block = (gc_block *)gc_base_cur;
    gc_base_cur += BLOCK_SIZE;
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
  arrput(nursery_blocks, block);
  return block;
}

static void block_free(gc_block *block) { arrput(free_blocks, block); }
static bool is_large_alloc(void *p);

static void mark_object_block(gc_header *hdr) {
  if (is_large_alloc(hdr)) {
    return;
  }
  gc_block *block = (gc_block *)((uintptr_t)hdr & ~(uintptr_t)(BLOCK_SIZE - 1));
  block->live_objects++;
}

static void clear_object_block(gc_header *hdr) {
  gc_block *block = (gc_block *)((uintptr_t)hdr & ~(uintptr_t)(BLOCK_SIZE - 1));
  assert(block->live_objects > 0);
  if (--block->live_objects == 0) {
    block_free(block);
  }
}

void gc_free(void) {
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
  while (!list_empty(&large_allocs)) {
    list_head *pos = large_allocs.next;
    list_del(pos);
    free(container_of(pos, struct large_alloc, list));
  }
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
  uintptr_t base = (uintptr_t)ctx;
  arrput(log_buf, ((log_item){(uintptr_t)field - base, v.value}));
}

NOINLINE void gc_log_slow(gc_obj obj) {
  gc_header *hdr = to_gc_header(obj);
  if (hdr->rc == 0) {
    return;
  }
  if (hdr->flags & GC_LOGGED) {
    return;
  }
  hdr->flags |= GC_LOGGED;
  arrput(log_buf, ((log_item){LOG_OBJ_HEADER, (uint64_t)hdr}));
  trace_heap_object(hdr, snapshot_field, hdr);
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

static bool is_large_alloc(void *p) {
  // This checks, using unsigned wraparound, that it is *not* in the
  // small object space.
  return (uintptr_t)p - (uintptr_t)gc_base >= gc_size;
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
  list_add_tail(&la->list, &large_allocs);
  arrput(large_nursery, (gc_header *)(la + 1));
  *(uint64_t *)(la + 1) = 0;
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
    copy_hp_end = (uintptr_t)block->data;
    copy_hp = (uintptr_t)block->data + BLOCK_DATA_SIZE;
    new_hp = copy_hp - sz;
    assert(new_hp >= copy_hp_end);
  }
  copy_hp = new_hp;
  return (gc_header *)copy_hp;
}

INLINE inline static void inc_visit(gc_obj *field, gc_field_stack *increments);

INLINE inline static void visit_root(gc_obj *root, gc_field_stack *increments) {
  inc_visit(root, increments);
  gc_obj_stack_push(&next_decrements, *root);
}

INLINE inline static void inc_trace_field(gc_obj *field, void *ctx) {
  gc_field_stack_push(ctx, field);
}

INLINE inline static void inc_visit(gc_obj *field, gc_field_stack *increments) {
  gc_obj obj = *field;
  if (!is_heap_object(obj)) {
    return;
  }
  gc_header *hdr = to_gc_header(obj);
  if (hdr->rc != 0) {
    hdr->rc++;
    return;
  }

  // rc == 0: object may need copying. Check forwarding first in case
  // another field already copied it.
  uint8_t tag = get_tag(obj);
  if (is_forwarded(hdr)) {
    hdr = forward_ptr(hdr);
    *field = tag_header(hdr, tag);
    hdr->rc++;
    return;
  }

  if (hdr->type != FUNC_TAG && !is_large_alloc(hdr)) {
    size_t sz = heap_align(heap_object_size(hdr));
    gc_header *copy = copy_alloc(sz);
    memcpy(copy, hdr, sz);
    copy->flags &= (uint8_t)~(GC_LOGGED | GC_FWD_TAG);
    copy->rc = 0;
    set_forward(hdr, copy);
    hdr = copy;
    *field = tag_header(hdr, tag);
  }
  hdr->rc = 1;
  mark_object_block(hdr);
  trace_heap_object(hdr, inc_trace_field, increments);
}

INLINE inline static void process_increments(gc_field_stack *increments) {
  while (increments->len) {
    gc_obj *field = gc_field_stack_pop(increments);
    inc_visit(field, increments);
  }
}

INLINE inline static void dec_trace_field(gc_obj *field, void *ctx) {
  gc_obj_stack_push(ctx, *field);
}

INLINE inline static void process_decrements(void) {
  gc_obj_stack *decrements = &cur_decrements;
  while (decrements->len) {
    gc_obj obj = gc_obj_stack_pop(decrements);
    gc_header *hdr = to_gc_header(obj);
    if (!is_heap_object(obj)) {
      continue;
    }
    // Deferred duplicate decrements can target an object already reclaimed or
    // forwarded by an earlier decrement in this batch.
    if (hdr->rc == 0) {
      continue;
    }
    if (--hdr->rc > 0) {
      continue;
    }

    trace_heap_object(hdr, dec_trace_field, decrements);
    if (is_large_alloc(hdr)) {
      struct large_alloc *la = (struct large_alloc *)hdr - 1;
      list_del(&la->list);
      free(la);
    } else {
      clear_object_block(hdr);
    }
  }
}

static void gc_add_mark_root(const uint64_t *rootp, size_t len) {
  gc_field_stack *increments = &cur_increments;
  uint64_t *slots = (uint64_t *)rootp;
  for (size_t i = 0; i < len; i++) {
    gc_obj v = {.value = (int64_t)slots[i]};
    visit_root(&v, increments);
    slots[i] = (uint64_t)v.value;
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
  struct timespec t4;
  clock_gettime(CLOCK_MONOTONIC, &t0);
  double mutator_ms = prev_gc_end.tv_sec ? elapsed_ms(prev_gc_end, t0) : 0.0;
  size_t free_before = arrlen(free_blocks);
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
        visit_root(&v, increments);
        slots[j] = (uintptr_t)to_raw_ptr(v);
      }
    } else {
      uint64_t *base = (uint64_t *)root.ptr;
      for (size_t j = 0; j < root.len; j++) {
        gc_obj v = {.value = (int64_t)base[j]};
        visit_root(&v, increments);
        base[j] = (uint64_t)v.value;
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
    assert(((gc_header *)obj)->rc != 0);

    i++;
    if (i >= arrlen(log_buf)) {
      break;
    }
    cur = log_buf[i];
    while (cur.offset != LOG_OBJ_HEADER) {
      gc_obj *field = (gc_obj *)((uint8_t *)obj + cur.offset);
      gc_field_stack_push(increments, field);
      gc_obj old_val = {.value = (int64_t)cur.val};
      if (is_heap_object(old_val) && to_gc_header(old_val)->rc != 0) {
        gc_obj_stack_push(&cur_decrements, old_val);
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

  // 3) Process *previous* decrements (could be in background thread)
  process_decrements();
  clock_gettime(CLOCK_MONOTONIC, &t3);

  // 4) Sweep nursery: free empty blocks and dead large allocs,
  //    leave live ones for decrements
  for (size_t i = 0; i < arrlen(nursery_blocks); i++) {
    if (nursery_blocks[i]->live_objects == 0) {
      block_free(nursery_blocks[i]);
    }
  }
  arrlen_set(nursery_blocks, 0);

  for (size_t i = 0; i < arrlen(large_nursery); i++) {
    gc_header *hdr = large_nursery[i];
    if (hdr->rc == 0) {
      struct large_alloc *la = (struct large_alloc *)hdr - 1;
      list_del(&la->list);
      free(la);
    }
  }
  arrlen_set(large_nursery, 0);

  next_collect = collect_after;

  // 5) Get a fresh block for allocation
  gc_block *fresh = block_alloc();
  gc_hp_end = (uintptr_t)fresh->data;
  gc_hp = (uintptr_t)fresh->data + BLOCK_DATA_SIZE;
  clock_gettime(CLOCK_MONOTONIC, &t4);

  size_t freed_mb =
      (arrlen(free_blocks) - free_before) * BLOCK_SIZE / (size_t)(1024 * 1024);
  size_t nursery_mb = copy_alloc_bytes / (size_t)(1024 * 1024);
  copy_alloc_bytes = 0;

  LOG(gc,
      "gc_collect: %.3f/+%.3f ms (roots %.3f, inc %.3f, dec %.3f, sweep %.3f), "
      "blocks: %zu total, %zu free (+%zu MB), nursery copy: %zu MB, "
      "buflen %li",
      elapsed_ms(t0, t4), mutator_ms, elapsed_ms(t0, t1), elapsed_ms(t1, t2),
      elapsed_ms(t2, t3), elapsed_ms(t3, t4), arrlen(all_blocks),
      arrlen(free_blocks), freed_mb, nursery_mb, buflen);
  prev_gc_end = t4;
  profiler_set_in_gc(false);
}

EXPORT uint64_t SCM_GC_CNT(void) { return total_gc_cnt; }
