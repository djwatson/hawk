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
  uintptr_t hp;
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
static uint64_t *stacktop;

static uintptr_t align_size(uintptr_t size) {
  return (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
}

static void gc_collect(void) {
  if (verbose) {
    fprintf(stderr, "gc_collect(): stub\n");
  }
}

void gc_init(void *stacktop_in) {
  size_t heap_size = 512UL << 20;
  char *heap_env = getenv("GC_SPACE");
  if (heap_env) {
    heap_size = (size_t)atoll(heap_env);
  }
  auto mem = mmap(nullptr, heap_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
  if (mem == MAP_FAILED) {
    fprintf(stderr, "Heap allocation failed: %zu bytes\n", heap_size);
    abort();
  }
  heap.mem = (uintptr_t)mem;
  heap.hp = (uintptr_t)mem;
  heap.limit = (uintptr_t)mem + heap_size;
  heap.size = heap_size;
  roots = nullptr;
  scan_callback = nullptr;
  scan_data = nullptr;
  stacktop = stacktop_in;
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

uint64_t *gc_get_stack_top() { return stacktop; }

void *gc_base_ptr(void *p) {
  uintptr_t cur = heap.mem;
  uintptr_t target = (uintptr_t)p;
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
  if (heap.mem) {
    munmap((void *)heap.mem, heap.size);
  }
  heap = (gc_heap){0};
  stacktop = nullptr;
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
