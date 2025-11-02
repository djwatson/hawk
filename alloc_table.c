#include "alloc_table.h"

void alloc_table_init(alloc_table *table, uintptr_t start, uintptr_t end) {
  table->min = start;
  table->size = end - start;
  table->table = malloc(sizeof(void *) * ((end - start) >> shift));
}

bool alloc_table_lookup(alloc_table *table, void *p, void **slab) {
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
                           uint64_t range) {
  uint64_t ps = (uint64_t)p;

  assert((range & ind_mask) == 0);
  assert((ps & ind_mask) == 0);

  for (uint64_t i = 0; i < (range >> shift); i++) {
    table->table[(ps - table->min) >> shift] = val;
    ps += ind_sz;
  }
}
