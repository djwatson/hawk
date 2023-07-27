#pragma once

#include <stdbool.h>
#include <stddef.h>

void *GC_malloc(size_t sz);
void *GC_realloc(void *ptr, size_t sz);
void GC_enable(bool en);

void GC_free(void *ptr);
void GC_init();

// *MUST* be in strict stack order.
void GC_push_root(long *root);
void GC_pop_root(const long *root);
