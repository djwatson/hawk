#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "util/util.h"

static constexpr uint64_t size_classes = 4096 / 8;

typedef struct slab_info slab_info;

typedef struct freelist_s {
  uint64_t start_ptr;
  uint64_t end_ptr;
  slab_info *slab;
} freelist_s;

typedef void (*gc_scan_root_cb)(const uint64_t *rootp, size_t len);
typedef void (*gc_scan_callback)(void *data, gc_scan_root_cb add_root);

extern freelist_s freelist[size_classes];

void gc_init(void *stacktop);
void gc_add_root(const uint64_t *rootp, size_t len);
void gc_remove_root(uint64_t const *rootp);
void gc_set_scan_callback(gc_scan_callback cb, void *data);
uint64_t *gc_get_stack_top();
void *gc_base_ptr(void *p);
void gc_log(uint64_t a);
void gc_free(void);

NOINLINE void *gc_alloc_slow(uint64_t sz);

static inline void *gc_alloc(uint64_t sz) {
  assert((sz & 0x7) == 0);
  uint64_t sz_class = sz / 8;
  if (unlikely(sz_class >= size_classes)) {
    return gc_alloc_slow(sz);
  }
  freelist_s *fl = &freelist[sz_class];
  uint64_t s = fl->start_ptr;
  uint64_t start = fl->start_ptr + (sz_class * 8);
  if (unlikely(start > fl->end_ptr)) {
    [[clang::musttail]] return gc_alloc_slow(sz);
  }
  fl->start_ptr = start;
  return (void *)s;
}
