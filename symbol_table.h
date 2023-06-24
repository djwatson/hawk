#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
typedef struct string_s string_s;
typedef struct symbol symbol;

symbol *symbol_table_find(string_s *str);
void symbol_table_insert(symbol *sym);
symbol *symbol_table_find_cstr(const char *str);
void symbol_table_clear();

// GC needs access.
typedef struct table {
  size_t cnt; // Number of objects currently in hash.
  size_t sz;  // Size of backing buffer.

  symbol *entries[];
} table;

#define TOMBSTONE ((symbol *)0x01)

extern table *sym_table;

#ifdef __cplusplus
}
#endif
