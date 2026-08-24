#define _DEFAULT_SOURCE

#include <sys/mman.h>

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "gc.h"
#include "log.h"
#include "profiler.h"
#include "types.h"
#include "util/stack.h"

enum : size_t {
  SLAB_SIZE = 16 * 1024,
  OLD_SMALL_MAX = 4096,
  SIZE_CLASS_COUNT = OLD_SMALL_MAX / 8 + 1,
  DEFAULT_NURSERY = 32 * 1024 * 1024,
  DEFAULT_OLD_COLLECT = 100000000,
  MAX_PAGE_ORDER = 31,
  SLAB_MARK_WORDS = SLAB_SIZE / sizeof(gc_obj) / 64,
};

enum region_kind { REGION_FREE, REGION_SLAB, REGION_LARGE };

typedef struct region {
  uint8_t *start;
  size_t bytes;
  uint8_t order;
  enum region_kind kind;
  void *owner;
} region;

typedef struct old_slab {
  region *region;
  size_t slot_size;
  size_t capacity;
  uint64_t mark_bits[SLAB_MARK_WORDS];
} old_slab;

typedef struct old_freelist {
  uint8_t *next;
  uint8_t *end;
  old_slab *slab;
} old_freelist;

typedef struct large_obj {
  region *region;
  size_t size;
  bool marked;
} large_obj;

STACK(gc_header_stack, gc_header *)

uintptr_t gc_hp;
uintptr_t gc_hp_end;
uintptr_t gc_nursery_start;
size_t gc_nursery_size;
gc_root_range gc_roots[GC_MAX_ROOTS];
size_t gc_roots_len;
size_t gc_size;
uint64_t total_gc_cnt;

static void *gc_mmap_base;
static size_t gc_mmap_size;
static uint8_t *heap_base;
static size_t heap_units;
static size_t heap_cursor;
static region **page_map;
static region **regions;
static region **free_pages[MAX_PAGE_ORDER];
static old_slab **old_slabs;
static old_freelist old_freelists[SIZE_CLASS_COUNT];
static old_slab **partial_slabs[SIZE_CLASS_COUNT];
static large_obj **large_objects;
static gc_header_stack worklist;
static gc_obj *logged_objects;
static gc_obj *sticky_objects;
static gc_obj *bcfunc_list;
static gc_obj *bcfunc_roots;
static bool bcfunc_list_unsorted;
static gc_scan_callback scan_callback;
static void *scan_data;
static gc_obj *stack_root_bottom;
static gc_obj **stack_root_top;
static gc_obj *stack_root_end;
static size_t nursery_limit;
static size_t old_since_collect;
static size_t next_old_collect = DEFAULT_OLD_COLLECT;
static unsigned old_collect_count;
static bool force_full;

static inline bool bit_test(uint64_t const *bits, size_t bit) {
  return bits[bit / 64] & (UINT64_C(1) << (bit % 64));
}

static inline void bit_set(uint64_t *bits, size_t bit) {
  bits[bit / 64] |= UINT64_C(1) << (bit % 64);
}

static uint8_t page_order(size_t bytes) {
  size_t units = (bytes + SLAB_SIZE - 1) / SLAB_SIZE;
  uint8_t order = 0;
  while (((size_t)1 << order) < units)
    order++;
  return order;
}

static region *region_alloc(uint8_t order, enum region_kind kind) {
  region *r;
  size_t units = (size_t)1 << order;
  if (arrlen(free_pages[order])) {
    r = arrpop_last(free_pages[order]);
  } else {
    uint8_t larger = order + 1;
    while (larger < MAX_PAGE_ORDER && !arrlen(free_pages[larger]))
      larger++;
    if (larger < MAX_PAGE_ORDER) {
      r = arrpop_last(free_pages[larger]);
      while (r->order > order) {
        r->order--;
        r->bytes /= 2;
        region *buddy = calloc(1, sizeof(*buddy));
        if (!buddy)
          abort();
        *buddy = (region){.start = r->start + r->bytes,
                          .bytes = r->bytes,
                          .order = r->order,
                          .kind = REGION_FREE};
        arrput(regions, buddy);
        size_t first = (buddy->start - heap_base) / SLAB_SIZE;
        for (size_t i = first; i < first + ((size_t)1 << buddy->order); i++)
          page_map[i] = buddy;
        arrput(free_pages[buddy->order], buddy);
      }
      goto found;
    }
    size_t start = (heap_cursor + units - 1) & ~(units - 1);
    if (start > heap_units || units > heap_units - start) {
      fprintf(stderr, "out of GC space: used %zu MB, request %zu KB\n",
              heap_cursor * SLAB_SIZE / (1024 * 1024),
              units * SLAB_SIZE / 1024);
      abort();
    }
    r = calloc(1, sizeof(*r));
    if (!r)
      abort();
    r->start = heap_base + start * SLAB_SIZE;
    r->bytes = units * SLAB_SIZE;
    r->order = order;
    heap_cursor = start + units;
    arrput(regions, r);
    for (size_t i = start; i < start + units; i++)
      page_map[i] = r;
  }
found:
  r->kind = kind;
  r->owner = nullptr;
  return r;
}

static void region_free(region *r) {
  r->kind = REGION_FREE;
  r->owner = nullptr;
  arrput(free_pages[r->order], r);
}

static inline region *lookup_region(void const *p) {
  uintptr_t a = (uintptr_t)p;
  uintptr_t base = (uintptr_t)heap_base;
  uintptr_t off = a - base;
  if (off >= gc_size)
    return nullptr;
  region *r = page_map[off / SLAB_SIZE];
  if (!r || r->kind == REGION_FREE || a < (uintptr_t)r->start ||
      a >= (uintptr_t)r->start + r->bytes)
    return nullptr;
  return r;
}

static inline region *lookup_old_region(void const *p) {
  uintptr_t off = (uintptr_t)p - (uintptr_t)heap_base;
  if (off >= gc_size)
    return nullptr;
  return page_map[off / SLAB_SIZE];
}

static inline size_t slab_mark_bit(old_slab const *slab, void const *p) {
  return ((uintptr_t)p - (uintptr_t)slab->region->start) / sizeof(gc_obj);
}

static old_slab *slab_new(size_t slot_size) {
  old_slab *slab = calloc(1, sizeof(*slab));
  if (!slab)
    abort();
  slab->region = region_alloc(0, REGION_SLAB);
  slab->region->owner = slab;
  slab->slot_size = slot_size;
  slab->capacity = SLAB_SIZE / slot_size;
  arrput(old_slabs, slab);
  old_since_collect += SLAB_SIZE;
  return slab;
}

static bool refill_old_range(size_t cls) {
  old_freelist *fl = &old_freelists[cls];
  for (;;) {
    old_slab *slab = fl->slab;
    size_t first = 0;
    if (slab) {
      first = (size_t)(fl->end - slab->region->start) / slab->slot_size;
    } else if (arrlen(partial_slabs[cls])) {
      slab = arrpop_last(partial_slabs[cls]);
    } else {
      return false;
    }
    size_t slot_words = slab->slot_size / sizeof(gc_obj);
    while (first < slab->capacity &&
           bit_test(slab->mark_bits, first * slot_words))
      first++;
    if (first == slab->capacity) {
      fl->slab = nullptr;
      continue;
    }
    size_t end = first + 1;
    while (end < slab->capacity &&
           !bit_test(slab->mark_bits, end * slot_words))
      end++;
    fl->slab = slab;
    fl->next = slab->region->start + first * slab->slot_size;
    fl->end = slab->region->start + end * slab->slot_size;
    return true;
  }
}

static void *small_old_alloc(size_t size, bool clear) {
  size_t cls = size / 8;
  old_freelist *fl = &old_freelists[cls];
  if (fl->next >= fl->end && !refill_old_range(cls)) {
    old_slab *slab = slab_new(size);
    fl->slab = slab;
    fl->next = slab->region->start;
    fl->end = slab->region->start + slab->capacity * size;
  }
  old_slab *slab = fl->slab;
  uint8_t *p = fl->next;
  fl->next += size;
  assert(!bit_test(slab->mark_bits, slab_mark_bit(slab, p)));
  if (clear)
    memset(p, 0, size);
  return p;
}

static inline void *cons_old_alloc(void) {
  old_freelist *fl = &old_freelists[sizeof(cons_s) / sizeof(gc_obj)];
  if (unlikely(fl->next >= fl->end))
    return small_old_alloc(sizeof(cons_s), false);
  void *p = fl->next;
  fl->next += sizeof(cons_s);
  return p;
}

static large_obj *large_new(size_t size, bool clear) {
  large_obj *large = calloc(1, sizeof(*large));
  if (!large)
    abort();
  large->region = region_alloc(page_order(size), REGION_LARGE);
  large->region->owner = large;
  large->size = size;
  old_since_collect += size;
  if (clear)
    memset(large->region->start, 0, size);
  ((gc_header *)large->region->start)->flags = GC_LARGE;
  arrput(large_objects, large);
  return large;
}

static void *old_alloc_raw(size_t size, bool clear) {
  assert((size & 7) == 0);
  if (size <= OLD_SMALL_MAX)
    return small_old_alloc(size, clear);
  return large_new(size, clear)->region->start;
}

void *gc_alloc_old(uint64_t size) {
  return old_alloc_raw((size_t)size, true);
}

static bool is_young(gc_header *hdr) {
  return (uintptr_t)hdr - gc_nursery_start < gc_nursery_size;
}

static gc_header *evacuate_cons(gc_header *hdr) {
  cons_s *copy = cons_old_alloc();
  *copy = *(cons_s *)hdr;
  copy->header.flags = 0;
  copy->header.rc = 0;
  set_forward(hdr, copy);
  gc_header_stack_push(&worklist, &copy->header);
  return &copy->header;
}

static gc_header *evacuate_other(gc_header *hdr) {
  assert((uintptr_t)hdr - gc_nursery_start < gc_nursery_size &&
         hdr->type != FUNC_TAG && hdr->type != CONS_TAG && !is_forwarded(hdr));
  size_t size = heap_align(heap_object_size(hdr));
  gc_header *copy = old_alloc_raw(size, false);
  memcpy(copy, hdr, size);
  copy->flags = size > OLD_SMALL_MAX ? GC_LARGE : 0;
  copy->rc = 0;
  set_forward(hdr, copy);
  gc_header_stack_push(&worklist, copy);
  return copy;
}

static void evacuate_field(gc_obj *field, void *ctx) {
  (void)ctx;
  if (!is_heap_object(*field))
    return;
  gc_header *hdr = to_gc_header(*field);
  if (!is_young(hdr))
    return;
  uint8_t type = hdr->type;
  gc_header *copy = type == FIXNUM_TAG   ? forward_ptr(hdr)
                    : type == CONS_TAG ? evacuate_cons(hdr)
                                       : evacuate_other(hdr);
  *field = tag_header(copy, get_tag(*field));
}

static void visit_explicit_roots(trace_callback visit) {
  if (stack_root_bottom) {
    assert(*stack_root_top >= stack_root_bottom &&
           *stack_root_top <= stack_root_end);
    for (gc_obj *slot = stack_root_bottom; slot < *stack_root_top; slot++)
      visit(slot, nullptr);
  }
  for (size_t i = 0; i < gc_roots_len; i++) {
    gc_root_range root = gc_roots[i];
    if (root.tag) {
      uintptr_t *slots = (uintptr_t *)root.ptr;
      for (size_t j = 0; j < root.len; j++) {
        if (!slots[j])
          continue;
        gc_obj obj = tag_header((gc_header *)slots[j], root.tag);
        visit(&obj, nullptr);
        slots[j] = (uintptr_t)to_raw_ptr(obj);
      }
    } else {
      gc_obj *slots = (gc_obj *)root.ptr;
      for (size_t j = 0; j < root.len; j++)
        visit(&slots[j], nullptr);
    }
  }
  for (size_t i = 0; i < arrlen(bcfunc_roots); i++)
    visit(&bcfunc_roots[i], nullptr);
}

static void evacuate_roots(uint64_t *roots, size_t len) {
  for (size_t i = 0; i < len; i++)
    evacuate_field((gc_obj *)&roots[i], nullptr);
}

static void visit_callback_roots(gc_scan_root_cb visit) {
  if (!scan_callback)
    return;
  scan_callback(scan_data, visit);
}

static void scan_logged_young(void) {
  for (size_t i = 0; i < arrlen(logged_objects); i++) {
    gc_header *hdr = to_gc_header(logged_objects[i]);
    trace_heap_object(hdr, hdr->type, evacuate_field, nullptr);
    hdr->flags &= (uint8_t)~GC_LOGGED;
  }
  arrlen_set(logged_objects, 0);
}

static void nursery_collect(void) {
  visit_explicit_roots(evacuate_field);
  visit_callback_roots(evacuate_roots);
  for (size_t i = 0; i < arrlen(bcfunc_roots); i++) {
    gc_header *hdr = to_gc_header(bcfunc_roots[i]);
    trace_heap_object(hdr, hdr->type, evacuate_field, nullptr);
  }
  scan_logged_young();
  while (worklist.len) {
    gc_header *hdr = gc_header_stack_pop(&worklist);
    if (hdr->type == CONS_TAG) {
      cons_s *cons = (cons_s *)hdr;
      evacuate_field(&cons->b, nullptr);
      evacuate_field(&cons->a, nullptr);
    } else {
      trace_heap_object(hdr, hdr->type, evacuate_field, nullptr);
    }
  }
  if (stack_root_bottom)
    memset(*stack_root_top, 0,
           (size_t)(stack_root_end - *stack_root_top) * sizeof(gc_obj));
  arrlen_set(bcfunc_roots, 0);
  gc_hp_end = gc_nursery_start;
  gc_hp = gc_nursery_start + gc_nursery_size;
}

static void mark_field(gc_obj *field, void *ctx) {
  (void)ctx;
  if (!is_heap_object(*field))
    return;
  gc_header *hdr = to_gc_header(*field);
  region *r = lookup_old_region(hdr);
  if (!r)
    return;
  if (r->kind == REGION_SLAB) {
    old_slab *slab = r->owner;
    size_t off = (uint8_t *)hdr - r->start;
    assert(off < slab->capacity * slab->slot_size &&
           off % slab->slot_size == 0);
    size_t bit = off / sizeof(gc_obj);
    if (bit_test(slab->mark_bits, bit))
      return;
    bit_set(slab->mark_bits, bit);
  } else if (r->kind == REGION_LARGE) {
    large_obj *large = r->owner;
    if (hdr != (gc_header *)r->start || large->marked)
      return;
    large->marked = true;
  } else {
    return;
  }
  gc_header_stack_push(&worklist, hdr);
}

static void mark_roots(uint64_t *roots, size_t len) {
  for (size_t i = 0; i < len; i++)
    mark_field((gc_obj *)&roots[i], nullptr);
}

static void drain_mark_worklist(void) {
  while (worklist.len) {
    gc_header *hdr = gc_header_stack_pop(&worklist);
    if (hdr->type == CONS_TAG) {
      cons_s *cons = (cons_s *)hdr;
      mark_field(&cons->b, nullptr);
      mark_field(&cons->a, nullptr);
    } else {
      trace_heap_object(hdr, hdr->type, mark_field, nullptr);
    }
  }
}

static bool old_object_marked(gc_header *hdr) {
  region *r = lookup_region(hdr);
  if (!r)
    return true;
  if (r->kind == REGION_SLAB) {
    old_slab *slab = r->owner;
    size_t off = (uint8_t *)hdr - r->start;
    return off < slab->capacity * slab->slot_size &&
           off % slab->slot_size == 0 &&
           bit_test(slab->mark_bits, off / sizeof(gc_obj));
  }
  if (r->kind == REGION_LARGE)
    return ((large_obj *)r->owner)->marked;
  return false;
}

static void consume_sticky_objects(bool full) {
  for (size_t i = 0; i < arrlen(sticky_objects); i++) {
    gc_header *hdr = to_gc_header(sticky_objects[i]);
    if (!full && old_object_marked(hdr))
      trace_heap_object(hdr, hdr->type, mark_field, nullptr);
    hdr->flags &= (uint8_t)~GC_STICKY_LOGGED;
  }
  arrlen_set(sticky_objects, 0);
}

static void prune_bcfuncs(void) {
  size_t out = 0;
  for (size_t i = 0; i < arrlen(bcfunc_list); i++) {
    gc_header *hdr = to_gc_header(bcfunc_list[i]);
    if (old_object_marked(hdr))
      bcfunc_list[out++] = bcfunc_list[i];
  }
  arrlen_set(bcfunc_list, out);
  bcfunc_list_unsorted = true;
}

static size_t sweep_old(size_t *freed) {
  size_t live = 0;
  *freed = 0;
  memset(old_freelists, 0, sizeof(old_freelists));
  for (size_t cls = 0; cls < SIZE_CLASS_COUNT; cls++) {
    if (partial_slabs[cls])
      arrlen_set(partial_slabs[cls], 0);
  }
  for (size_t i = 0; i < arrlen(old_slabs);) {
    old_slab *slab = old_slabs[i];
    size_t count = 0;
    for (size_t word = 0; word < SLAB_MARK_WORDS; word++)
      count += (size_t)__builtin_popcountll(slab->mark_bits[word]);
    size_t marked = count * slab->slot_size;
    live += marked;
    if (marked) {
      if (marked < SLAB_SIZE / 2)
        arrput(partial_slabs[slab->slot_size / 8], slab);
      i++;
      continue;
    }
    *freed += SLAB_SIZE;
    region_free(slab->region);
    free(slab);
    old_slabs[i] = arrpop_last(old_slabs);
  }
  for (size_t i = 0; i < arrlen(large_objects);) {
    large_obj *large = large_objects[i];
    if (large->marked) {
      live += large->size;
      i++;
      continue;
    }
    *freed += large->size;
    region_free(large->region);
    free(large);
    large_objects[i] = arrpop_last(large_objects);
  }
  return live;
}

static void clear_marks(void) {
  arr_for_each(old_slabs, slab) {
    memset(slab->mark_bits, 0, SLAB_MARK_WORDS * sizeof(uint64_t));
  }
  arr_for_each(large_objects, large) { large->marked = false; }
}

static void old_collect(void) {
  bool full = force_full || ++old_collect_count == 9;
  if (old_collect_count == 9)
    old_collect_count = 0;
  if (full)
    clear_marks();
  visit_explicit_roots(mark_field);
  visit_callback_roots(mark_roots);
  consume_sticky_objects(full);
  drain_mark_worklist();
  prune_bcfuncs();
  size_t freed = 0;
  size_t live = sweep_old(&freed);
  if (full && next_old_collect < live)
    next_old_collect = live;
  force_full = !full && freed < next_old_collect / 2;
  old_since_collect = 0;
  LOG(gc, "old collect: full %d, live %zu, freed %zu, next %zu", full,
      live, freed, next_old_collect);
}

void gc_collect(void) {
  total_gc_cnt++;
  profiler_set_in_gc(true);
  nursery_collect();
  if (old_since_collect >= next_old_collect)
    old_collect();
  profiler_set_in_gc(false);
}

NOINLINE void *gc_alloc_slow(uint64_t size) {
  assert((size & 7) == 0);
  uintptr_t next = gc_hp - size;
  if (gc_hp && next >= gc_hp_end) {
    gc_hp = next;
    *(uint64_t *)gc_hp = 0;
    return (void *)gc_hp;
  }
  if (size > gc_nursery_size) {
    if (old_since_collect >= next_old_collect)
      gc_collect();
    return old_alloc_raw((size_t)size, true);
  }
  gc_collect();
  MUSTTAIL return gc_alloc_slow(size);
}

NOINLINE void gc_log_slow(gc_obj obj) {
  gc_header *hdr = to_gc_header(obj);
  region *r = lookup_region(hdr);
  if (!r)
    return;
  if (hdr->flags & GC_LOGGED)
    return;
  hdr->flags |= GC_LOGGED;
  if (r->kind == REGION_SLAB || r->kind == REGION_LARGE) {
    arrput(logged_objects, obj);
    if (!(hdr->flags & GC_STICKY_LOGGED)) {
      hdr->flags |= GC_STICKY_LOGGED;
      arrput(sticky_objects, obj);
    }
  }
}

static int cmp_bcfunc(const void *ap, const void *bp) {
  uintptr_t a = (uintptr_t)to_raw_ptr(*(gc_obj const *)ap);
  uintptr_t b = (uintptr_t)to_raw_ptr(*(gc_obj const *)bp);
  return (a > b) - (a < b);
}

static int cmp_bcfunc_range(const void *kp, const void *ep) {
  uintptr_t p = *(uintptr_t const *)kp;
  bcfunc *func = to_func(*(gc_obj const *)ep);
  uintptr_t base = (uintptr_t)func;
  if (p < base)
    return -1;
  return p >= base + heap_object_size(func) ? 1 : 0;
}

void gc_register_bcfunc(bcfunc *func) {
  gc_obj obj = tag_func(func);
  arrput(bcfunc_list, obj);
  if (lookup_region(func)) {
    arrput(bcfunc_roots, obj);
    gc_log_slow(obj);
  }
  bcfunc_list_unsorted = true;
}

void *gc_base_ptr(void *p) {
  if (!arrlen(bcfunc_list))
    return nullptr;
  if (bcfunc_list_unsorted) {
    qsort(bcfunc_list, arrlen(bcfunc_list), sizeof(gc_obj), cmp_bcfunc);
    bcfunc_list_unsorted = false;
  }
  gc_obj *found = bsearch(&p, bcfunc_list, arrlen(bcfunc_list), sizeof(gc_obj),
                          cmp_bcfunc_range);
  return found ? to_raw_ptr(*found) : nullptr;
}

void gc_set_scan_callback(gc_scan_callback cb, void *data) {
  scan_callback = cb;
  scan_data = data;
}

void gc_set_stack_root(gc_obj *bottom, gc_obj **top, gc_obj *end) {
  stack_root_bottom = bottom;
  stack_root_top = top;
  stack_root_end = end;
}

void gc_init(void) {
  char *env = getenv("GC_SPACE");
  size_t mb = env ? (size_t)atoll(env) : 2048;
  gc_size = mb * 1024 * 1024;
  env = getenv("GC_COLLECT");
  nursery_limit = env ? (size_t)atoll(env) * 1024 * 1024 : DEFAULT_NURSERY;
  gc_nursery_size = (nursery_limit + SLAB_SIZE - 1) & ~(SLAB_SIZE - 1);
  if (!gc_nursery_size)
    gc_nursery_size = SLAB_SIZE;
  gc_mmap_size = gc_size + gc_nursery_size + SLAB_SIZE;
  gc_mmap_base = mmap(nullptr, gc_mmap_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
  if (gc_mmap_base == MAP_FAILED) {
    perror("mmap gc space");
    abort();
  }
  gc_nursery_start = ((uintptr_t)gc_mmap_base + SLAB_SIZE - 1) &
                     ~(uintptr_t)(SLAB_SIZE - 1);
  gc_hp_end = gc_nursery_start;
  gc_hp = gc_nursery_start + gc_nursery_size;
  heap_base = (uint8_t *)(gc_nursery_start + gc_nursery_size);
  heap_units = gc_size / SLAB_SIZE;
  page_map = calloc(heap_units, sizeof(*page_map));
  if (!page_map)
    abort();
  LOG(gc, "GC_SPACE: %zu MB", mb);
}

void gc_free(void) {
  arr_for_each(old_slabs, slab) {
    free(slab);
  }
  arr_for_each(large_objects, large) {
    free(large);
  }
  arr_for_each(regions, r) { free(r); }
  for (size_t i = 0; i < MAX_PAGE_ORDER; i++)
    arrfree(free_pages[i]);
  for (size_t i = 0; i < SIZE_CLASS_COUNT; i++)
    arrfree(partial_slabs[i]);
  arrfree(regions);
  arrfree(old_slabs);
  arrfree(large_objects);
  free(worklist.data);
  arrfree(logged_objects);
  arrfree(sticky_objects);
  arrfree(bcfunc_list);
  arrfree(bcfunc_roots);
  free(page_map);
  if (gc_mmap_base && gc_mmap_base != MAP_FAILED)
    munmap(gc_mmap_base, gc_mmap_size);
}

EXPORT uint64_t SCM_GC_CNT(void) { return total_gc_cnt; }
