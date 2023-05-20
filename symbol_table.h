#pragma once

#include "types.h"

symbol* symbol_table_find(string_s* str);
void symbol_table_insert(string_s* str, symbol* sym);

