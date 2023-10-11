// Copyright 2023 Dave Watson

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "defs.h"
#include "types.h"

#define LOGGED_MARK (1UL << 31)

extern uint8_t *alloc_start;
extern uint8_t *alloc_ptr;
extern uint8_t *alloc_end;
NOINLINE void *GC_malloc_slow(size_t sz);
inline INLINE void *GC_malloc(size_t sz) {
  assert(alloc_ptr >= alloc_start);
  auto aligned_sz = (sz + 7) & ~TAG_MASK;
  auto res = alloc_ptr;
  alloc_ptr += aligned_sz;
  if (alloc_ptr < alloc_end) {
    return res;
  }
  return GC_malloc_slow(aligned_sz);
}
inline INLINE void *GC_malloc_no_collect(size_t sz) {
  auto aligned_sz = (sz + 7) & ~TAG_MASK;
  auto res = alloc_ptr;
  alloc_ptr += aligned_sz;
  if (alloc_ptr < alloc_end) {
    return res;
  }
  return NULL;
}
void *GC_realloc(void *ptr, size_t sz);
void GC_collect();
void GC_log_obj_slow(void *obj) asm("GC_log_obj_slow");
static inline bool is_logged(uint32_t rc) { return rc & LOGGED_MARK; }
inline INLINE void GC_log_obj(void *ptr) {
  uint32_t rc = ((uint32_t *)ptr)[1];
  if (unlikely(rc != 0 && !is_logged(rc))) {
    MUSTTAIL return GC_log_obj_slow(ptr);
  }
  assert(((uint32_t *)ptr)[1] != LOGGED_MARK);
}

void GC_free(void *ptr);
void GC_init();

// *MUST* be in strict stack order.
void GC_push_root(gc_obj *root);
void GC_pop_root(const gc_obj *root);
