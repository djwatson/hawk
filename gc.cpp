#include "gc.h"

#include <stdlib.h>

#include "types.h"
#include "bytecode.h"
#include "symbol_table.h"

extern long *stack;
extern unsigned int stacksz;

// Static roots are the stack - stacksz,
// the symbol table,
// and the constant table.
//
// Currently functions aren't GC'd.
static void trace_roots() {
  for(size_t i = 0; i < stacksz; i++)  {
    if (stack[i] != 0) {
      print_obj(stack[i]);
    }
  }
  for(size_t i = 0; i < const_table_sz; i++)  {
    if (const_table[i] != 0) {
      print_obj(const_table[i]);
    }
  }
  for(size_t i = 0; i < sym_table->sz; i++) {
    auto&cur = sym_table->entries[i];
    if (cur != nullptr && cur != TOMBSTONE) {
      print_obj((long)cur + SYMBOL_TAG);
    }
  }
}

void* GC_malloc(size_t sz) {
  trace_roots();
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
