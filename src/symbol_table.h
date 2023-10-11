// Copyright 2023 Dave Watson

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "types.h"

typedef struct string_s string_s;
typedef struct symbol symbol;

symbol *symbol_table_find(string_s *str);
// Inserts a string_s, making a copy of it for the new symbol.
// Returns the tagged symbol object, or 0 if can_alloc = false and we
// need a GC.
gc_obj symbol_table_insert(string_s *str, bool can_alloc);
symbol *symbol_table_find_cstr(const char *str);
void symbol_table_clear();

typedef int64_t gc_obj;

// GC needs access.
typedef struct table {
  size_t cnt; // Number of objects currently in hash.
  size_t sz;  // Size of backing buffer.

  gc_obj entries[];
} table;

typedef void (*for_each_cb)(gc_obj *field);
void symbol_table_for_each(for_each_cb cb);

#define TOMBSTONE 1

extern table *sym_table;
