#pragma once

#include <stddef.h>
#include <stdint.h>

void gc_init(void *stacktop);
void gc_add_root(uint64_t *rootp, size_t len);
void gc_remove_root(uint64_t const *rootp);
uint64_t *gc_get_stack_top();
void gc_log(uint64_t a);
void *gc_alloc(uint64_t sz);
