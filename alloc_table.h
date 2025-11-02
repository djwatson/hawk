#pragma once

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

static constexpr uint64_t shift = 12;
static constexpr uint64_t ind_sz = 1 << shift;
static constexpr uint64_t ind_mask = (ind_sz - 1);

typedef struct alloc_table {
  uint64_t min;
  uint64_t size;

  void **table;
} alloc_table;

bool alloc_table_lookup(alloc_table *table, void *p, void **slab);
void alloc_table_set_range(alloc_table *table, void *val, void *p,
                           uint64_t range);
void alloc_table_init(alloc_table *table, uintptr_t start, uintptr_t end);
