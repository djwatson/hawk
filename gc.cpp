#include "gc.h"

#include <stdlib.h>

#include "types.h"

extern long *stack;
extern unsigned int stacksz;

static void trace_roots() {
  for(size_t i = 0; i < stacksz; i++)  {
    if (stack[i] != 0) {
      print_obj(stack[i]);
    }
  }
}

void* GC_malloc(size_t sz) {
  //trace_roots();
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
