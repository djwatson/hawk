#define _DEFAULT_SOURCE

#include <sys/mman.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "gc.h"
#include "hawk.h"
#include "hashtable.h"
#include "types.h"

typedef struct {
  uintptr_t mem;
  uintptr_t hp;
  uintptr_t from_space;
  uintptr_t to_space;
  uintptr_t limit;
  size_t size;
} gc_heap;

typedef struct {
  const uint64_t *ptr;
  size_t len;
} root_range;

static gc_heap heap;
static root_range *roots;
static gc_scan_callback scan_callback;
static void *scan_data;
static gc_header **worklist;

typedef struct {
  gc_header *key;
  gc_header *value;
} moved_entry;

typedef struct {
  bcfunc *ptr;
} pinned_func_entry;

static moved_entry *moved_objs;
static pinned_func_entry *pinned_funcs;

static uintptr_t align_size(uintptr_t size) {
  return (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
}

static uintptr_t space_size(void) { return heap.size / 2; }

static bool in_space(uintptr_t p, uintptr_t base) {
  return p >= base && p < base + space_size();
}

static bool is_pinned_func(gc_header *obj) {
  if (!obj || obj->type != FUNC_TAG) {
    return false;
  }
  arr_for_each(pinned_funcs, entry) {
    if ((gc_header *)entry.ptr == obj) {
      return true;
    }
  }
  return false;
}

static void scan_object(gc_header *obj);

static void visit_field(gc_obj *slot, void *ctx) {
  (void)ctx;
  if (!is_heap_object(*slot)) {
    return;
  }
  gc_header *obj = to_gc_header(*slot);
  if (is_pinned_func(obj) || !in_space((uintptr_t)obj, heap.from_space)) {
    return;
  }
  auto moved = hm_getp_null(moved_objs, obj);
  if (moved) {
    *slot = tag_header(moved->value, get_tag(*slot));
    return;
  }
  size_t sz = align_size(heap_object_size(obj));
  if (heap.hp + sz > heap.limit) {
    fprintf(stderr, "out of memory during collection\n");
    abort();
  }
  gc_header *copy = (gc_header *)heap.hp;
  memcpy(copy, obj, sz);
  heap.hp += sz;
  hm_put(moved_objs, obj, copy);
  *slot = tag_header(copy, get_tag(*slot));
  arrput(worklist, copy);
}

static void scan_root_range(const uint64_t *start, const uint64_t *end) {
  const uint64_t *lo = start;
  const uint64_t *hi = end;
  if (hi < lo) {
    lo = end;
    hi = start;
  }
  for (const uint64_t *p = lo; p < hi; p++) {
    visit_field((gc_obj *)p, nullptr);
  }
}

static void gc_add_mark_root(const uint64_t *rootp, size_t len) {
  if (!rootp || len == 0) {
    return;
  }
  scan_root_range(rootp, rootp + len);
}

static void flip_spaces(void) {
  heap.hp = heap.from_space;
  heap.from_space = heap.to_space;
  heap.to_space = heap.hp;
  heap.limit = heap.hp + space_size();
}

static void scan_object(gc_header *obj) {
  trace_heap_object(obj, visit_field, nullptr);
}

static void gc_collect(void) {
  if (verbose) {
    fprintf(stderr, "gc_collect()\n");
  }
  flip_spaces();
  hm_free(moved_objs);
  moved_objs = nullptr;
  arrlen_set(worklist, 0);

  arr_for_each(roots, root) { gc_add_mark_root(root.ptr, root.len); }
  if (scan_callback) {
    scan_callback(scan_data, gc_add_mark_root);
  }
  arr_for_each(pinned_funcs, entry) { arrput(worklist, &entry.ptr->header); }

  while (arrlen(worklist) > 0) {
    gc_header *obj = *arrlast(worklist);
    arrpop(worklist);
    scan_object(obj);
  }
}

void gc_init(void) {
  size_t heap_size = 512UL << 20;
  char *heap_env = getenv("GC_SPACE");
  if (heap_env) {
    heap_size = (size_t)atoll(heap_env);
  }
  auto mem = mmap(nullptr, heap_size * 2, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
  if (mem == MAP_FAILED) {
    fprintf(stderr, "Heap allocation failed: %zu bytes\n", heap_size * 2);
    abort();
  }
  heap.mem = (uintptr_t)mem;
  heap.to_space = (uintptr_t)mem;
  heap.from_space = (uintptr_t)mem + heap_size;
  heap.hp = (uintptr_t)mem;
  heap.limit = (uintptr_t)mem + heap_size;
  heap.size = heap_size * 2;
  roots = nullptr;
  scan_callback = nullptr;
  scan_data = nullptr;
  worklist = nullptr;
  moved_objs = nullptr;
  pinned_funcs = nullptr;
}

void gc_add_root(const uint64_t *rootp, size_t len) {
  arrput(roots, ((root_range){.ptr = rootp, .len = len}));
}

void gc_remove_root(uint64_t const *rootp) {
  for (size_t i = 0; i < arrlen(roots); i++) {
    if (roots[i].ptr == rootp) {
      roots[i] = *arrlast(roots);
      arrpop(roots);
      return;
    }
  }
#ifndef NDEBUG
  assert(!"Attempted to remove unknown GC root");
#endif
}

void gc_set_scan_callback(gc_scan_callback cb, void *data) {
  scan_callback = cb;
  scan_data = data;
}

void gc_register_bcfunc(bcfunc *func) {
  arrput(pinned_funcs, ((pinned_func_entry){.ptr = func}));
}

void *gc_base_ptr(void *p) {
  arr_for_each(pinned_funcs, entry) {
    uintptr_t start = (uintptr_t)entry.ptr;
    uintptr_t end = start + heap_object_size(entry.ptr);
    uintptr_t target = (uintptr_t)p;
    if (start <= target && target < end) {
      return entry.ptr;
    }
  }
  uintptr_t active = heap.to_space;
  uintptr_t cur = heap.mem;
  uintptr_t target = (uintptr_t)p;
  cur = active;
  while (cur < heap.hp) {
    size_t sz = heap_object_size((void *)cur);
    uintptr_t next = cur + align_size(sz);
    if (cur <= target && target < next) {
      return (void *)cur;
    }
    cur = next;
  }
  return p;
}

void gc_log(uint64_t a) { (void)a; }

void gc_free(void) {
  arrfree(roots);
  arrfree(worklist);
  hm_free(moved_objs);
  arr_for_each(pinned_funcs, entry) { free(entry.ptr); }
  arrfree(pinned_funcs);
  if (heap.mem) {
    munmap((void *)heap.mem, heap.size);
  }
  heap = (gc_heap){0};
  scan_callback = nullptr;
  scan_data = nullptr;
}

NOINLINE void *gc_alloc_slow(uint64_t sz) {
  uintptr_t addr = heap.hp;
  uintptr_t new_hp = align_size(addr + sz);
  if (new_hp > heap.limit) {
    gc_collect();
    addr = heap.hp;
    new_hp = align_size(addr + sz);
    if (new_hp > heap.limit) {
      fprintf(stderr, "out of memory %" PRIu64 "\n", sz);
      abort();
    }
  }
  heap.hp = new_hp;
  return (void *)addr;
}
