#pragma once

#include <stddef.h>

void *GC_malloc(size_t sz);
void *GC_realloc(void *ptr, size_t sz);
void GC_enable(bool en);

void GC_free(void *ptr);
void GC_init();

// *MUST* be in strict stack order.
void GC_push_root(long *ptr);
void GC_pop_root(long *ptr);
