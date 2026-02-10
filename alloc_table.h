#pragma once

#include "hawk.h"

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

static inline INLINE bool alloc_table_lookup(alloc_table *table, void *p,
                                             void **slab) {
  uint64_t ps = (uint64_t)p;

  if ((ps - table->min) > table->size) {
    return false;
  }

  auto entry = table->table[(ps - table->min) >> shift];
  if (entry) {
    *slab = entry;
    return true;
  }
  return false;
}

void alloc_table_set_range(alloc_table *table, void *val, void *p,
                           uint64_t range);
void alloc_table_init(alloc_table *table, uintptr_t start, uintptr_t end);
void alloc_table_free(alloc_table *table);
