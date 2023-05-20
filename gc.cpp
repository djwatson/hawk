#include "gc.h"

#include <stdlib.h>
#include <assert.h>

#include "types.h"
#include "bytecode.h"
#include "symbol_table.h"

extern long *stack;
extern unsigned int stacksz;

static bool gc_enable = true;

static uint8_t* alloc_ptr = nullptr;
static uint8_t* alloc_end = nullptr;

void GC_enable(bool en) {
  gc_enable = en;
}

static bool is_forwarded(long obj) {
  auto ptr = (long*)obj;
  if (((*ptr)&TAG_MASK) == FORWARD_TAG) {
    return true;
  }
  return false;
}

static void set_forward(long obj, long to) {
  auto ptr = (long*)obj;
  assert(((*ptr)&TAG_MASK) == 0);
  *ptr = to + FORWARD_TAG;
}

static long get_forward(long obj) {
  assert(is_forwarded(obj));
  auto ptr = (long*)obj;
  return (*ptr) - FORWARD_TAG;
}

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

static constexpr size_t alloc_sz = 4096*20;
void* GC_malloc(size_t sz) {
  sz = (sz+7)&(~TAG_MASK);
  assert((sz&TAG_MASK) == 0);
  //trace_roots();
  auto res = alloc_ptr;
  alloc_ptr += sz;
  if (alloc_ptr < alloc_end) {
    return res;
  }

  // Slowpath.
  if (sz >= alloc_sz) {
    printf("LArge alloc: %li\n", sz);
    assert(false);
  }
  alloc_ptr = (uint8_t*)malloc(alloc_sz);
  alloc_end = alloc_ptr + alloc_sz;
  res = alloc_ptr;
  alloc_ptr += sz;
  return res;
}

void* GC_realloc(void* ptr, size_t sz) {
  // TODO zero-mem
  return realloc(ptr, sz);
}

void GC_free(void* ptr) {
  free(ptr);
}
