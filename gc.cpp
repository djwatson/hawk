#include "gc.h"

#include <stdlib.h>

void* GC_malloc(size_t sz) {
  auto res = calloc(sz, 1);
  return res;
}

void* GC_realloc(void* ptr, size_t sz) {
  // TODO zero-mem
  return realloc(ptr, sz);
}

void GC_free(void* ptr) {
  free(ptr);
}
