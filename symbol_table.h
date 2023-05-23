#pragma once

#include "types.h"

symbol *symbol_table_find(string_s *str);
void symbol_table_insert(symbol *sym);
symbol *symbol_table_find_cstr(const char *str);

// GC needs access.
struct table {
  size_t cnt; // Number of objects currently in hash.
  size_t sz;  // Size of backing buffer.

  symbol *entries[];
};

#define TOMBSTONE ((symbol *)0x01)

extern table *sym_table;
