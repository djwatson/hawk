// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include <stdlib.h>
#include <string.h>

#include "zone_alloc.h"

#include "array.h"

static uintptr_t align(uintptr_t val, uintptr_t alignment) {
  return (val + alignment - 1) & ~(alignment - 1);
}
static uintptr_t align_size(uintptr_t size) {
  return align(size, sizeof(uintptr_t));
}

static void *zone_malloc_slow(zone *z, size_t sz) {
  size_t new_sz = sz > DEFAULT_SZ ? sz : DEFAULT_SZ;
  auto n = calloc(1, new_sz);
  if (!n) {
    abort();
  }

  arrput(nullptr, z->regions, n);
  z->cur = n;
  z->end = n + new_sz;
  return zone_malloc(z, sz);
}

void *zone_malloc(zone *z, size_t sz) {
  // TODO(davejwatson) alignment?
  sz = align_size(sz);

  if (z->cur + sz <= z->end) {
    auto ret = z->cur;
    z->cur += sz;
    return ret;
  }

  // Keep the fastpath fast.
  return zone_malloc_slow(z, sz);
}

void *zone_realloc(zone *z, void const *prev, size_t prev_size, size_t sz) {
  // TODO(davejwatson): Could optimize more?
  auto res = zone_malloc(z, sz);
  if (prev && prev_size) {
    memcpy(res, prev, prev_size);
  }
  return res;
}

void zone_free(zone *z) {
  arr_for_each(z->regions, region) { free(region); }
  arrfree(z->regions);
  memset(z, 0, sizeof(zone));
}
