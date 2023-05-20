#pragma once

#include <stddef.h>

void* GC_malloc(size_t sz);
void* GC_realloc(void* ptr, size_t sz);
void GC_enable(bool en);

void GC_free(void* ptr);

