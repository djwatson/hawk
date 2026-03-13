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
#include "types.h"

typedef struct {
  uintptr_t mem;
  uintptr_t from_space;
  uintptr_t to_space;
  size_t size;
} gc_heap;

typedef struct {
  const uint64_t *ptr;
  size_t len;
} root_range;

static gc_heap heap;
uintptr_t gc_hp;
uintptr_t gc_limit;
static root_range *roots;
static gc_scan_callback scan_callback;
static void *scan_data;
static gc_header **worklist;

typedef struct {
  bcfunc *ptr;
} pinned_func_entry;

static pinned_func_entry *pinned_funcs;

enum : uint64_t {
  FORWARD_TAG = UINT64_MAX,
};

typedef struct {
  uint64_t fwdtag;
  gc_header *fwd;
} gc_forward;

static uintptr_t align_size(uintptr_t size) {
  return (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
}

static uintptr_t space_size(void) { return heap.size / 2; }

static bool in_space(uintptr_t p, uintptr_t base) {
  return p >= base && p < base + space_size();
}

static bool is_forwarded(gc_header const *obj) {
  return ((gc_forward const *)obj)->fwdtag == FORWARD_TAG;
}

static gc_header *forwarded(gc_header const *obj) {
  return ((gc_forward const *)obj)->fwd;
}

static void forward_obj(gc_header *obj, gc_header *new_obj) {
  gc_forward *fwd = (gc_forward *)obj;
  fwd->fwd = new_obj;
  fwd->fwdtag = FORWARD_TAG;
}

static void scan_object(gc_header *obj);

static void visit_field(gc_obj *slot, void *ctx) {
  (void)ctx;
  if (!is_heap_object(*slot)) {
    return;
  }
  gc_header *obj = to_gc_header(*slot);
  if (!in_space((uintptr_t)obj, heap.from_space)) {
    return;
  }
  if (is_forwarded(obj)) {
    *slot = tag_header(forwarded(obj), get_tag(*slot));
    return;
  }
  size_t sz = align_size(heap_object_size(obj));
  uintptr_t new_hp = gc_hp - sz;
  if (new_hp < gc_limit) {
    fprintf(stderr, "out of memory during collection, increate GC_SPACE\n");
    abort();
  }
  gc_hp = new_hp;
  gc_header *copy = (gc_header *)gc_hp;
  memcpy(copy, obj, sz);
  forward_obj(obj, copy);
  *slot = tag_header(copy, get_tag(*slot));
  arrput(worklist, copy);
}

static void scan_root_range(const uint64_t *start, const uint64_t *end) {
  assert(start <= end);
  for (const uint64_t *p = start; p < end; p++) {
    visit_field((gc_obj *)p, nullptr);
  }
}

static void gc_add_mark_root(const uint64_t *rootp, size_t len) {
  assert(rootp);
  assert(len != 0);
  scan_root_range(rootp, rootp + len);
}

static void flip_spaces(void) {
  // memset((void *)heap.from_space, 0, space_size());
  uintptr_t new_space = heap.from_space;
  heap.from_space = heap.to_space;
  heap.to_space = new_space;
  gc_hp = heap.to_space + space_size();
  gc_limit = heap.to_space;
}

static void scan_object(gc_header *obj) {
  trace_heap_object(obj, visit_field, nullptr);
}

static void gc_collect(void) {
  if (verbose) {
    fprintf(stderr, "gc_collect()\n");
  }
  flip_spaces();
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
  gc_hp = (uintptr_t)mem + heap_size;
  gc_limit = (uintptr_t)mem;
  heap.size = heap_size * 2;
}

void gc_add_root(const uint64_t *rootp, size_t len) {
  arrput(roots, ((root_range){.ptr = rootp, .len = len}));
}

void gc_remove_root(uint64_t const *rootp) {
  for (size_t i = arrlen(roots); i > 0; i--) {
    size_t idx = i - 1;
    if (roots[idx].ptr == rootp) {
      roots[idx] = *arrlast(roots);
      arrpop(roots);
      return;
    }
  }
  assert(!"Attempted to remove unknown GC root");
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
  return nullptr;
}

void gc_log(uint64_t a) {
  (void)a;
  abort();
}

void gc_free(void) {
  arrfree(roots);
  arrfree(worklist);
  arr_for_each(pinned_funcs, entry) { free(entry.ptr); }
  arrfree(pinned_funcs);
  munmap((void *)heap.mem, heap.size);
}

NOINLINE void *gc_alloc_slow(uint64_t sz) {
  gc_collect();
  uintptr_t new_hp = gc_hp - align_size(sz);
  if (new_hp < gc_limit) {
    fprintf(stderr, "out of memory %" PRIu64 "\n", sz);
    abort();
  }
  gc_hp = new_hp;
  return (void *)gc_hp;
}
