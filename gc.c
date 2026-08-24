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

enum : size_t {
  SLAB_SIZE = 16 * 1024,
  NURSERY_SIZE = 256 * 1024,
  OLD_SMALL_MAX = 4096,
  SIZE_CLASS_COUNT = OLD_SMALL_MAX / 8 + 1,
  DEFAULT_NURSERY = 32 * 1024 * 1024,
  DEFAULT_OLD_COLLECT = 100000000,
  MAX_PAGE_ORDER = 31,
};

enum region_kind { REGION_FREE, REGION_NURSERY, REGION_SLAB, REGION_LARGE };

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
  uint64_t *alloc_bits;
  uint64_t *mark_bits;
  uint64_t dirty_bits[SLAB_SIZE / 8 / 64];
} old_slab;

typedef struct large_obj {
  region *region;
  size_t size;
  uint64_t *dirty_bits;
  bool marked;
  bool young;
} large_obj;

uintptr_t gc_hp;
uintptr_t gc_hp_end;
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
static region **nursery_blocks;
static old_slab **old_slabs;
static old_slab *class_cursor[SIZE_CLASS_COUNT];
static large_obj **large_objects;
static gc_obj *worklist;
static gc_obj *bcfunc_list;
static gc_obj *bcfunc_roots;
static bool bcfunc_list_unsorted;
static gc_scan_callback scan_callback;
static void *scan_data;
static gc_obj *stack_root_bottom;
static gc_obj **stack_root_top;
static gc_obj *stack_root_end;
static size_t nursery_limit;
static size_t nursery_bytes;
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

static inline void bit_clear(uint64_t *bits, size_t bit) {
  bits[bit / 64] &= ~(UINT64_C(1) << (bit % 64));
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

static region *lookup_region(void const *p) {
  uintptr_t a = (uintptr_t)p;
  uintptr_t base = (uintptr_t)heap_base;
  if (a < base || a >= base + heap_units * SLAB_SIZE)
    return nullptr;
  region *r = page_map[(a - base) / SLAB_SIZE];
  if (!r || r->kind == REGION_FREE || a < (uintptr_t)r->start ||
      a >= (uintptr_t)r->start + r->bytes)
    return nullptr;
  return r;
}

static old_slab *slab_new(size_t slot_size) {
  old_slab *slab = calloc(1, sizeof(*slab));
  if (!slab)
    abort();
  slab->region = region_alloc(0, REGION_SLAB);
  slab->region->owner = slab;
  slab->slot_size = slot_size;
  slab->capacity = SLAB_SIZE / slot_size;
  size_t words = (slab->capacity + 63) / 64;
  slab->alloc_bits = calloc(words, sizeof(uint64_t));
  slab->mark_bits = calloc(words, sizeof(uint64_t));
  if (!slab->alloc_bits || !slab->mark_bits)
    abort();
  arrput(old_slabs, slab);
  return slab;
}

static size_t slab_free_slot(old_slab *slab) {
  for (size_t i = 0; i < slab->capacity; i++) {
    if (!bit_test(slab->alloc_bits, i))
      return i;
  }
  return SIZE_MAX;
}

static void *small_old_alloc(size_t size) {
  size_t cls = size / 8;
  old_slab *slab = class_cursor[cls];
  size_t slot = slab ? slab_free_slot(slab) : SIZE_MAX;
  if (slot == SIZE_MAX) {
    slab = nullptr;
    arr_for_each(old_slabs, candidate) {
      if (candidate->slot_size != size)
        continue;
      slot = slab_free_slot(candidate);
      if (slot != SIZE_MAX) {
        slab = candidate;
        break;
      }
    }
    if (!slab) {
      slab = slab_new(size);
      slot = 0;
    }
    class_cursor[cls] = slab;
  }
  bit_set(slab->alloc_bits, slot);
  bit_clear(slab->mark_bits, slot);
  void *p = slab->region->start + slot * size;
  memset(p, 0, size);
  return p;
}

static large_obj *large_new(size_t size, bool young) {
  large_obj *large = calloc(1, sizeof(*large));
  if (!large)
    abort();
  large->region = region_alloc(page_order(size), REGION_LARGE);
  large->region->owner = large;
  large->size = size;
  large->young = young;
  size_t words = ((size + 7) / 8 + 63) / 64;
  large->dirty_bits = calloc(words, sizeof(uint64_t));
  if (!large->dirty_bits)
    abort();
  memset(large->region->start, 0, size);
  ((gc_header *)large->region->start)->flags = GC_LARGE;
  arrput(large_objects, large);
  return large;
}

static void *old_alloc_raw(size_t size) {
  assert((size & 7) == 0);
  old_since_collect += size;
  if (size <= OLD_SMALL_MAX)
    return small_old_alloc(size);
  return large_new(size, false)->region->start;
}

void *gc_alloc_old(uint64_t size) { return old_alloc_raw((size_t)size); }

static region *nursery_block_alloc(void) {
  region *r = region_alloc(page_order(NURSERY_SIZE), REGION_NURSERY);
  arrput(nursery_blocks, r);
  nursery_bytes += NURSERY_SIZE;
  gc_hp_end = (uintptr_t)r->start;
  gc_hp = gc_hp_end + NURSERY_SIZE;
  return r;
}

static bool is_young(gc_header *hdr) {
  region *r = lookup_region(hdr);
  if (!r)
    return false;
  if (r->kind == REGION_NURSERY)
    return true;
  return r->kind == REGION_LARGE && ((large_obj *)r->owner)->young;
}

static gc_header *evacuate(gc_header *hdr) {
  region *r = lookup_region(hdr);
  assert(r);
  if (r->kind == REGION_LARGE) {
    large_obj *large = r->owner;
    assert(large->young);
    large->young = false;
    old_since_collect += large->size;
    arrput(worklist, tag_header(hdr, hdr->type < 8 ? hdr->type : PTR_TAG));
    return hdr;
  }
  assert(r->kind == REGION_NURSERY && hdr->type != FUNC_TAG);
  if (is_forwarded(hdr))
    return forward_ptr(hdr);
  size_t size = heap_align(heap_object_size(hdr));
  gc_header *copy = old_alloc_raw(size);
  uint8_t alloc_flags = copy->flags;
  memcpy(copy, hdr, size);
  copy->flags = alloc_flags & GC_LARGE;
  copy->rc = 0;
  set_forward(hdr, copy);
  arrput(worklist,
         tag_header(copy, copy->type < 8 ? copy->type : PTR_TAG));
  return copy;
}

static void evacuate_field(gc_obj *field, void *ctx) {
  (void)ctx;
  if (!is_heap_object(*field))
    return;
  gc_header *hdr = to_gc_header(*field);
  if (!is_young(hdr))
    return;
  *field = tag_header(evacuate(hdr), get_tag(*field));
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

static void scan_dirty_young(void) {
  size_t slab_count = arrlen(old_slabs);
  for (size_t s = 0; s < slab_count; s++) {
    old_slab *slab = old_slabs[s];
    for (size_t word = 0; word < SLAB_SIZE / 8; word++) {
      if (!bit_test(slab->dirty_bits, word))
        continue;
      size_t slot = word * 8 / slab->slot_size;
      if (slot < slab->capacity && bit_test(slab->alloc_bits, slot))
        evacuate_field((gc_obj *)(slab->region->start + word * 8), nullptr);
    }
  }
  size_t large_count = arrlen(large_objects);
  for (size_t l = 0; l < large_count; l++) {
    large_obj *large = large_objects[l];
    if (large->young)
      continue;
    size_t words = (large->size + 7) / 8;
    for (size_t i = 0; i < words; i++) {
      if (bit_test(large->dirty_bits, i))
        evacuate_field((gc_obj *)(large->region->start + i * 8), nullptr);
    }
  }
}

static void nursery_collect(void) {
  visit_explicit_roots(evacuate_field);
  visit_callback_roots(evacuate_roots);
  scan_dirty_young();
  while (arrlen(worklist)) {
    gc_header *hdr = to_gc_header(arrpop_last(worklist));
    trace_heap_object(hdr, hdr->type, evacuate_field, nullptr);
  }
  for (size_t i = 0; i < arrlen(large_objects);) {
    large_obj *large = large_objects[i];
    if (!large->young) {
      i++;
      continue;
    }
    region_free(large->region);
    free(large->dirty_bits);
    free(large);
    large_objects[i] = arrpop_last(large_objects);
  }
  if (stack_root_bottom)
    memset(*stack_root_top, 0,
           (size_t)(stack_root_end - *stack_root_top) * sizeof(gc_obj));
  arr_for_each(nursery_blocks, r) { region_free(r); }
  arrlen_set(nursery_blocks, 0);
  arrlen_set(bcfunc_roots, 0);
  nursery_bytes = 0;
  gc_hp = gc_hp_end = 0;
}

static void mark_field(gc_obj *field, void *ctx) {
  (void)ctx;
  if (!is_heap_object(*field))
    return;
  gc_header *hdr = to_gc_header(*field);
  region *r = lookup_region(hdr);
  if (!r)
    return;
  if (r->kind == REGION_SLAB) {
    old_slab *slab = r->owner;
    size_t off = (uint8_t *)hdr - r->start;
    if (off % slab->slot_size)
      return;
    size_t slot = off / slab->slot_size;
    if (slot >= slab->capacity || !bit_test(slab->alloc_bits, slot) ||
        bit_test(slab->mark_bits, slot))
      return;
    bit_set(slab->mark_bits, slot);
  } else if (r->kind == REGION_LARGE) {
    large_obj *large = r->owner;
    if (large->young || hdr != (gc_header *)r->start || large->marked)
      return;
    large->marked = true;
  } else {
    return;
  }
  trace_heap_object(hdr, hdr->type, mark_field, nullptr);
}

static void mark_roots(uint64_t *roots, size_t len) {
  for (size_t i = 0; i < len; i++)
    mark_field((gc_obj *)&roots[i], nullptr);
}

static bool marked_owner(old_slab *slab, size_t word) {
  size_t slot = word * 8 / slab->slot_size;
  return slot < slab->capacity && bit_test(slab->alloc_bits, slot) &&
         bit_test(slab->mark_bits, slot);
}

static void mark_dirty(void) {
  arr_for_each(old_slabs, slab) {
    for (size_t word = 0; word < SLAB_SIZE / 8; word++) {
      if (bit_test(slab->dirty_bits, word) && marked_owner(slab, word))
        mark_field((gc_obj *)(slab->region->start + word * 8), nullptr);
    }
    memset(slab->dirty_bits, 0, sizeof(slab->dirty_bits));
  }
  arr_for_each(large_objects, large) {
    size_t words = (large->size + 7) / 8;
    if (large->marked) {
      for (size_t i = 0; i < words; i++) {
        if (bit_test(large->dirty_bits, i))
          mark_field((gc_obj *)(large->region->start + i * 8), nullptr);
      }
    }
    memset(large->dirty_bits, 0, ((words + 63) / 64) * sizeof(uint64_t));
  }
}

static bool old_object_marked(gc_header *hdr) {
  region *r = lookup_region(hdr);
  if (!r)
    return true;
  if (r->kind == REGION_SLAB) {
    old_slab *slab = r->owner;
    size_t off = (uint8_t *)hdr - r->start;
    size_t slot = off / slab->slot_size;
    return off % slab->slot_size == 0 && slot < slab->capacity &&
           bit_test(slab->alloc_bits, slot) &&
           bit_test(slab->mark_bits, slot);
  }
  if (r->kind == REGION_LARGE)
    return ((large_obj *)r->owner)->marked;
  return false;
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

static size_t sweep_old(void) {
  size_t live = 0;
  for (size_t i = 0; i < arrlen(old_slabs);) {
    old_slab *slab = old_slabs[i];
    size_t count = 0;
    for (size_t slot = 0; slot < slab->capacity; slot++) {
      if (!bit_test(slab->alloc_bits, slot))
        continue;
      if (!bit_test(slab->mark_bits, slot))
        bit_clear(slab->alloc_bits, slot);
      else
        count++;
    }
    live += count * slab->slot_size;
    if (count) {
      i++;
      continue;
    }
    if (class_cursor[slab->slot_size / 8] == slab)
      class_cursor[slab->slot_size / 8] = nullptr;
    region_free(slab->region);
    free(slab->alloc_bits);
    free(slab->mark_bits);
    free(slab);
    old_slabs[i] = arrpop_last(old_slabs);
  }
  for (size_t i = 0; i < arrlen(large_objects);) {
    large_obj *large = large_objects[i];
    if (large->young || large->marked) {
      if (!large->young)
        live += large->size;
      i++;
      continue;
    }
    region_free(large->region);
    free(large->dirty_bits);
    free(large);
    large_objects[i] = arrpop_last(large_objects);
  }
  return live;
}

static void clear_marks(void) {
  arr_for_each(old_slabs, slab) {
    size_t words = (slab->capacity + 63) / 64;
    memset(slab->mark_bits, 0, words * sizeof(uint64_t));
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
  if (!full)
    mark_dirty();
  else {
    arr_for_each(old_slabs, slab) {
      memset(slab->dirty_bits, 0, sizeof(slab->dirty_bits));
    }
    arr_for_each(large_objects, large) {
      size_t words = ((large->size + 7) / 8 + 63) / 64;
      memset(large->dirty_bits, 0, words * sizeof(uint64_t));
    }
  }
  prune_bcfuncs();
  size_t before = 0;
  arr_for_each(old_slabs, slab) {
    for (size_t i = 0; i < slab->capacity; i++)
      before += bit_test(slab->alloc_bits, i) ? slab->slot_size : 0;
  }
  arr_for_each(large_objects, large) {
    before += large->young ? 0 : large->size;
  }
  size_t live = sweep_old();
  size_t freed = before - live;
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
  nursery_block_alloc();
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
  if (size >= NURSERY_SIZE / 2) {
    if (nursery_bytes >= nursery_limit)
      gc_collect();
    large_obj *large = large_new((size_t)size, true);
    nursery_bytes += size;
    return large->region->start;
  }
  if (nursery_bytes >= nursery_limit)
    gc_collect();
  else
    nursery_block_alloc();
  MUSTTAIL return gc_alloc_slow(size);
}

NOINLINE void gc_log_slow(gc_obj *field) {
  region *r = lookup_region(field);
  if (!r)
    return;
  if (r->kind == REGION_SLAB) {
    old_slab *slab = r->owner;
    size_t off = (uint8_t *)field - r->start;
    size_t slot = off / slab->slot_size;
    if (slot < slab->capacity && bit_test(slab->alloc_bits, slot))
      bit_set(slab->dirty_bits, off / 8);
  } else if (r->kind == REGION_LARGE) {
    large_obj *large = r->owner;
    if (!large->young && (uint8_t *)field < r->start + large->size)
      bit_set(large->dirty_bits, ((uint8_t *)field - r->start) / 8);
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

static void log_func_field(gc_obj *field, void *ctx) {
  (void)ctx;
  gc_log_slow(field);
}

void gc_register_bcfunc(bcfunc *func) {
  gc_obj obj = tag_func(func);
  arrput(bcfunc_list, obj);
  if (lookup_region(func)) {
    arrput(bcfunc_roots, obj);
    trace_heap_object(&func->header, FUNC_TAG, log_func_field, nullptr);
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
  gc_mmap_size = gc_size + NURSERY_SIZE;
  gc_mmap_base = mmap(nullptr, gc_mmap_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
  if (gc_mmap_base == MAP_FAILED) {
    perror("mmap gc space");
    abort();
  }
  heap_base = (uint8_t *)(((uintptr_t)gc_mmap_base + NURSERY_SIZE - 1) &
                          ~(uintptr_t)(NURSERY_SIZE - 1));
  heap_units = gc_size / SLAB_SIZE;
  page_map = calloc(heap_units, sizeof(*page_map));
  if (!page_map)
    abort();
  LOG(gc, "GC_SPACE: %zu MB", mb);
}

void gc_free(void) {
  arr_for_each(old_slabs, slab) {
    free(slab->alloc_bits);
    free(slab->mark_bits);
    free(slab);
  }
  arr_for_each(large_objects, large) {
    free(large->dirty_bits);
    free(large);
  }
  arr_for_each(regions, r) { free(r); }
  for (size_t i = 0; i < MAX_PAGE_ORDER; i++)
    arrfree(free_pages[i]);
  arrfree(regions);
  arrfree(nursery_blocks);
  arrfree(old_slabs);
  arrfree(large_objects);
  arrfree(worklist);
  arrfree(bcfunc_list);
  arrfree(bcfunc_roots);
  free(page_map);
  if (gc_mmap_base && gc_mmap_base != MAP_FAILED)
    munmap(gc_mmap_base, gc_mmap_size);
}

EXPORT uint64_t SCM_GC_CNT(void) { return total_gc_cnt; }
