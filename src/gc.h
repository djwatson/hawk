#pragma once

#include <stdbool.h>
#include <stddef.h>

void __attribute__((always_inline)) * GC_malloc_no_collect(size_t sz);
void __attribute__((always_inline)) * GC_malloc(size_t sz);
void *GC_realloc(void *ptr, size_t sz);
void GC_enable(bool en);
void GC_collect();
void __attribute__((always_inline)) GC_log_obj(void *obj);
void GC_log_obj_slow(void *obj);

void GC_free(void *ptr);
void GC_init();

// *MUST* be in strict stack order.
void GC_push_root(long *root);
void GC_pop_root(const long *root);
