// Copyright 2023 Dave Watson

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "types.h"

typedef struct string_s string_s;
typedef struct symbol symbol;

void sym_table_init();
symbol *symbol_table_find(string_s *str);
// Inserts a string_s, making a copy of it for the new symbol.
// Returns the tagged symbol object, or 0 if can_alloc = false and we
// need a GC.
gc_obj symbol_table_insert(string_s *str, bool can_alloc);
symbol *symbol_table_find_cstr(const char *str);
void symbol_table_clear();

typedef void (*for_each_cb)(gc_obj *field);
void symbol_table_for_each(for_each_cb cb);
