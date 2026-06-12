#define _DEFAULT_SOURCE

#include <sys/mman.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

#include "array.h"
#include "gc.h"
#include "hawk.h"
#include "log.h"
#include "profiler.h"
#include "types.h"
#include "util/list.h"
#include "vm.h"

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
static size_t gc_size;
static uintptr_t gc_base_cur;
static gc_block **free_blocks;
static gc_scan_callback scan_callback;
static void *scan_data;
static uint64_t total_gc_cnt;
static LIST_HEAD(large_allocs);
static gc_block **all_blocks;
static gc_block **nursery_blocks;
static gc_header **large_nursery;
static size_t collect_after;
static size_t next_collect;
static gc_obj *bcfunc_list;
static gc_obj *bcfunc_roots;

typedef struct {
  gc_obj **data;
  size_t len;
  size_t cap;
} gc_field_stack;

typedef struct {
  gc_obj *data;
  size_t len;
  size_t cap;
} gc_obj_stack;

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

static void gc_collect(void);

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

NOINLINE static void *gc_stack_grow(void *data, size_t elem_size, size_t *cap) {
  size_t new_cap = *cap ? *cap * 2 : 256;
  void *new_data = realloc(data, elem_size * new_cap);
  if (!new_data) {
    fprintf(stderr, "gc_stack_grow: out of memory\n");
    abort();
  }
  *cap = new_cap;
  return new_data;
}

INLINE inline static void gc_field_stack_push(gc_field_stack *stack,
                                              gc_obj *field) {
  if (unlikely(stack->len == stack->cap)) {
    stack->data = gc_stack_grow(stack->data, sizeof(*stack->data), &stack->cap);
  }
  stack->data[stack->len++] = field;
}

INLINE inline static gc_obj *gc_field_stack_pop(gc_field_stack *stack) {
  return stack->data[--stack->len];
}

INLINE inline static void gc_obj_stack_push(gc_obj_stack *stack, gc_obj obj) {
  if (unlikely(stack->len == stack->cap)) {
    stack->data = gc_stack_grow(stack->data, sizeof(*stack->data), &stack->cap);
  }
  stack->data[stack->len++] = obj;
}

INLINE inline static gc_obj gc_obj_stack_pop(gc_obj_stack *stack) {
  return stack->data[--stack->len];
}

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
  if (p < base)
    return -1;
  size_t sz = heap_object_size(func);
  if (p >= base + sz)
    return 1;
  return 0;
}

void gc_register_bcfunc(bcfunc *func) {
  gc_obj tagged = tag_func(func);
  arrput(bcfunc_list, tagged);
  arrput(bcfunc_roots, tagged);
  qsort(bcfunc_list, arrlen(bcfunc_list), sizeof(gc_obj), cmp_bcfunc);
}

void gc_set_scan_callback(gc_scan_callback cb, void *data) {
  scan_callback = cb;
  scan_data = data;
}

void *gc_base_ptr(void *p) {
  if (arrlen(bcfunc_list) == 0)
    return nullptr;
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

static void set_forward(gc_header *hdr, void *ptr) {
  hdr->flags |= GC_FWD_TAG;
  *(void **)(hdr + 1) = ptr;
}
static bool is_forwarded(gc_header *hdr) { return hdr->flags & GC_FWD_TAG; }
static void *forward_ptr(gc_header *hdr) { return *(void **)(hdr + 1); }

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
  return (double)(e.tv_sec - s.tv_sec) * 1000.0 +
         (double)(e.tv_nsec - s.tv_nsec) / 1000000.0;
}

static void gc_collect(void) {
  total_gc_cnt++;

  {
    auto tmp = cur_decrements;
    cur_decrements = next_decrements;
    next_decrements = tmp;
    next_decrements.len = 0;
  }

  static struct timespec prev_gc_end;
  struct timespec t0, t1, t2, t3, t4;
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
  for (size_t i = 0; i < arrlen(nursery_blocks); i++)
    if (nursery_blocks[i]->live_objects == 0)
      block_free(nursery_blocks[i]);
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
      (arrlen(free_blocks) - free_before) * BLOCK_SIZE / (1024 * 1024);
  size_t nursery_mb = copy_alloc_bytes / (1024 * 1024);
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

// GC image reading.

enum : uint64_t { IMAGE_VERSION = 2 };
enum : size_t { IMAGE_HEADER_SIZE = 44 };

typedef struct {
  uintptr_t base;
  size_t len;
} image_ctx;

static gc_header *copy_image_obj(gc_header *obj, image_ctx const *image);

static void fixup_image_field(gc_obj *field, void *ctx) {
  if (!is_heap_object(*field))
    return;
  image_ctx const *image = ctx;
  uintptr_t offset = (uintptr_t)to_raw_ptr(*field);
  if (offset >= image->len) {
    fprintf(stderr, "read_image: pointer offset %" PRIuPTR " out of bounds\n",
            offset);
    abort();
  }
  gc_header *copy = copy_image_obj((gc_header *)(image->base + offset), image);
  *field = tag_header(copy, get_tag(*field));
}

static gc_header *copy_image_obj(gc_header *obj, image_ctx const *image) {
  if (is_forwarded(obj)) {
    return forward_ptr(obj);
  }
  size_t sz = heap_align(heap_object_size(obj));
  if ((uintptr_t)obj + sz > image->base + image->len) {
    fprintf(stderr, "read_image: object extends beyond image\n");
    abort();
  }
  gc_header *copy = (gc_header *)gc_alloc_slow(sz);
  memcpy(copy, obj, sz);
  copy->rc = 0;
  copy->flags = 0;
  set_forward(obj, copy);
  if (copy->type == FUNC_TAG) {
    gc_register_bcfunc((bcfunc *)copy);
  }
  trace_heap_object(copy, fixup_image_field, (void *)image);
  return copy;
}

static gc_obj loaded_error_symbol;
static bool loaded_error_symbol_rooted;

gc_obj gc_error_symbol(void) { return loaded_error_symbol; }

gc_obj gc_read_image(uint8_t const *data, size_t data_len, char const *path,
                     bool compressed) {
  LOG(gc, "image load");
  if (data_len < IMAGE_HEADER_SIZE) {
    fprintf(stderr, "read_image: file too short\n");
    abort();
  }
  if (memcmp(data, "HAWK", 4) != 0) {
    fprintf(stderr, "read_image: invalid magic\n");
    abort();
  }
  uint64_t version, gc_cnt_u64, image_len_u64, start_u64, error_u64;
  memcpy(&version, &data[4], sizeof(version));
  memcpy(&gc_cnt_u64, &data[12], sizeof(gc_cnt_u64));
  memcpy(&image_len_u64, &data[20], sizeof(image_len_u64));
  memcpy(&start_u64, &data[28], sizeof(start_u64));
  memcpy(&error_u64, &data[36], sizeof(error_u64));
  if (version != IMAGE_VERSION) {
    fprintf(stderr, "read_image: unsupported version\n");
    abort();
  }
  total_gc_cnt = gc_cnt_u64 + 1;
  size_t image_len = (size_t)image_len_u64;

  void *stage = mmap(nullptr, image_len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
  if (stage == MAP_FAILED) {
    fprintf(stderr, "read_image: failed to mmap staging\n");
    abort();
  }
  uintptr_t image_base = (uintptr_t)stage;

  uint8_t const *payload = data + IMAGE_HEADER_SIZE;
  size_t payload_len = data_len - IMAGE_HEADER_SIZE;
  if (!compressed) {
    if (payload_len != image_len) {
      fprintf(stderr, "read_image: length mismatch\n");
      abort();
    }
    memcpy((void *)image_base, payload, image_len);
  } else {
    size_t res =
        ZSTD_decompress((void *)image_base, image_len, payload, payload_len);
    if (ZSTD_isError(res)) {
      fprintf(stderr, "read_image: zstd: %s\n", ZSTD_getErrorName(res));
      abort();
    }
    if (res != image_len) {
      fprintf(stderr, "read_image: decompressed length mismatch\n");
      abort();
    }
  }

  image_ctx image = {.base = image_base, .len = image_len};

  gc_obj start = {.value = (int64_t)start_u64};
  loaded_error_symbol = (gc_obj){.value = (int64_t)error_u64};

  // Trace from roots: rc 0→1, trace children, bump live_objects
  fixup_image_field(&start, &image);
  fixup_image_field(&loaded_error_symbol, &image);
  if (!loaded_error_symbol_rooted) {
    gc_add_root((const void *)&loaded_error_symbol, 1, 0);
    loaded_error_symbol_rooted = true;
  }
  gc_add_root(&start, 1, 0);
  LOG(gc, "image done");
  gc_collect();
  gc_remove_root(&start, 0);

  munmap(stage, image_len);
  return start;
}

gc_obj gc_read_image_file(char const *path) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    perror("fopen");
    abort();
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    perror("fseek");
    abort();
  }
  long fsize = ftell(fp);
  if (fsize < 0) {
    perror("ftell");
    abort();
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    perror("fseek");
    abort();
  }
  if (fsize < (long)IMAGE_HEADER_SIZE) {
    fprintf(stderr, "read_image_file: file too short\n");
    abort();
  }

  uint8_t *buf = malloc((size_t)fsize);
  if (!buf) {
    fprintf(stderr, "Failed to allocate %li bytes\n", fsize);
    abort();
  }
  if (fread(buf, 1, (size_t)fsize, fp) != (size_t)fsize) {
    fprintf(stderr, "read_image_file: short read\n");
    abort();
  }
  fclose(fp);
  bool compressed = (size_t)fsize > IMAGE_HEADER_SIZE &&
                    ZSTD_isFrame(buf + IMAGE_HEADER_SIZE,
                                 (size_t)fsize - IMAGE_HEADER_SIZE) != 0;
  gc_obj result = gc_read_image(buf, (size_t)fsize, path, compressed);
  free(buf);
  return result;
}

EXPORT uint64_t SCM_GC_CNT(void) { return total_gc_cnt; }

typedef struct {
  uint8_t *base;
  size_t len;
  gc_header **worklist;
} dump_ctx;

static gc_header *dump_copy_object(gc_header *obj, dump_ctx *ctx) {
  if (is_forwarded(obj)) {
    return (gc_header *)forward_ptr(obj);
  }
  size_t sz = heap_align(heap_object_size(obj));
  gc_header *copy = (gc_header *)(ctx->base + ctx->len);
  memcpy(copy, obj, sz);
  copy->flags = 0;
  copy->aux = 0;
  copy->rc = 0;
  ctx->len += sz;
  set_forward(obj, copy);
  arrput(ctx->worklist, copy);
  return copy;
}

static void dump_visit_field(gc_obj *field, void *ctx) {
  if (!is_heap_object(*field))
    return;
  dump_ctx *dc = ctx;
  gc_header *obj = to_gc_header(*field);
  if (is_forwarded(obj)) {
    *field = tag_header((gc_header *)forward_ptr(obj), get_tag(*field));
    return;
  }
  gc_header *copy = dump_copy_object(obj, dc);
  *field = tag_header(copy, get_tag(*field));
}

static void dump_rebase_field(gc_obj *field, void *ctx) {
  if (!is_heap_object(*field))
    return;
  uint8_t *base = ctx;
  uintptr_t offset = (uintptr_t)to_raw_ptr(*field) - (uintptr_t)base;
  *field = (gc_obj){.value = (int64_t)offset + get_tag(*field)};
}

void gc_dump_image_and_die(gc_obj clo, gc_obj path, gc_obj compress_level) {
  vm_trace_reset();
  if (!is_closure(clo)) {
    fprintf(stderr, "gc_dump_image: not a closure\n");
    abort();
  }
  if (!is_string(path)) {
    fprintf(stderr, "gc_dump_image: path not a string\n");
    abort();
  }

  char const *filename = to_string(path)->str;
  bool do_compress = compress_level.value != FALSE_REP.value;
  int level = 0;
  if (do_compress) {
    level = (int)to_fixnum(compress_level);
  }

  uint8_t *data = malloc(gc_size);
  if (!data) {
    fprintf(stderr, "gc_dump_image: out of memory\n");
    abort();
  }

  dump_ctx dc = {.base = data, .len = 0, .worklist = nullptr};

  gc_obj root = clo;
  gc_obj start = to_closure(clo)->v[0];
  dump_visit_field(&root, &dc);
  dump_visit_field(&start, &dc);
  dump_visit_field(&loaded_error_symbol, &dc);

  while (arrlen(dc.worklist) > 0) {
    gc_header *obj = arrpop_last(dc.worklist);
    trace_heap_object(obj, dump_visit_field, &dc);
  }

  // rebase to offsets
  uintptr_t scan = (uintptr_t)data;
  uintptr_t end = scan + dc.len;
  while (scan < end) {
    gc_header *obj = (gc_header *)scan;
    trace_heap_object(obj, dump_rebase_field, data);
    scan += heap_align(heap_object_size(obj));
  }
  dump_rebase_field(&root, data);
  dump_rebase_field(&start, data);
  dump_rebase_field(&loaded_error_symbol, data);

  uint8_t *payload = data;
  size_t payload_len = dc.len;
  uint8_t *compressed = nullptr;
  if (do_compress) {
    size_t compressed_cap = ZSTD_compressBound(dc.len);
    compressed = malloc(compressed_cap);
    if (!compressed) {
      fprintf(stderr, "gc_dump_image: out of memory\n");
      abort();
    }
    size_t compressed_len =
        ZSTD_compress(compressed, compressed_cap, data, dc.len, level);
    if (ZSTD_isError(compressed_len)) {
      fprintf(stderr, "gc_dump_image: zstd: %s\n",
              ZSTD_getErrorName(compressed_len));
      abort();
    }
    payload = compressed;
    payload_len = compressed_len;
  }

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    perror("fopen");
    abort();
  }
  uint64_t image_len = dc.len;
  uint64_t gc_cnt = total_gc_cnt;
  uint64_t start_u64 = (uint64_t)start.value;
  uint64_t error_u64 = (uint64_t)loaded_error_symbol.value;
  uint64_t version = IMAGE_VERSION;
  if (fwrite("HAWK", 1, 4, fp) != 4 ||
      fwrite(&version, sizeof(version), 1, fp) != 1 ||
      fwrite(&gc_cnt, sizeof(gc_cnt), 1, fp) != 1 ||
      fwrite(&image_len, sizeof(image_len), 1, fp) != 1 ||
      fwrite(&start_u64, sizeof(start_u64), 1, fp) != 1 ||
      fwrite(&error_u64, sizeof(error_u64), 1, fp) != 1 ||
      fwrite(payload, 1, payload_len, fp) != payload_len || fclose(fp) != 0) {
    fprintf(stderr, "gc_dump_image: write error\n");
    abort();
  }

  arrfree(dc.worklist);
  free(compressed);
  free(data);
  exit(EXIT_SUCCESS);
}
