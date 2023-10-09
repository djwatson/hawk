// Copyright 2023 Dave Watson

#pragma once

#include <stddef.h>
#include <stdint.h>
typedef struct string_s string_s;
typedef struct symbol symbol;

symbol *symbol_table_find(string_s *str);
void symbol_table_insert(symbol *sym);
symbol *symbol_table_find_cstr(const char *str);
void symbol_table_clear();

typedef int64_t gc_obj;

// GC needs access.
typedef struct table {
  size_t cnt; // Number of objects currently in hash.
  size_t sz;  // Size of backing buffer.

  gc_obj entries[];
} table;

#define TOMBSTONE 1

extern table *sym_table;
