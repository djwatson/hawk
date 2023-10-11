// Copyright 2023 Dave Watson

#include "symbol_table.h"
#include <assert.h> // for assert
#include <stdbool.h>
#include <stdint.h> // for uint64_t
#include <stdlib.h> // for calloc, free, size_t
#include <string.h> // for strcmp

#include "defs.h"
#include "gc.h"
#include "types.h" // for string_s, symbol

#define auto __auto_type

/* FNV-1a */
uint64_t str_hash(const char *str) {
  const char *p = str;
  uint64_t hash = 0xcbf29ce484222325;

  while (*p++ != 0) {
    hash ^= *p;
    hash *= 0x100000001b3;
  }

  return hash;
}

// string_s* to symbol* hash table.
// Size must be power of two.
// Bottom bits may be tombstone.
// Open coded.

// TODO(djwatson) weak GC syms, and evict entries when they are collected.

// Non-empty default table so we don't have to null check.
static table empty_table = {0, 0};
table *sym_table = &empty_table;

symbol *symbol_table_find(string_s *str) {
  return symbol_table_find_cstr(str->str);
}

EXPORT symbol *symbol_table_find_cstr(const char *str) {
  auto hash = str_hash(str);

  auto mask = sym_table->sz - 1;
  for (size_t i = 0; i < sym_table->sz; i++) {
    auto cur = &sym_table->entries[(i + hash) & mask];
    if (*cur == 0) {
      return NULL;
    }
    if (*cur == TOMBSTONE) {
      continue;
    }
    symbol *curs = to_symbol(*cur);
    string_s *sym_name = get_sym_name(curs);
    if (strcmp(sym_name->str, str) == 0) {
      return curs;
    } // Mismatched comparison, continue.
  }

  return NULL;
}

static void rehash();
static void symbol_table_insert_sym(symbol *sym) {
  if ((sym_table->cnt + 1) > (sym_table->sz / 2)) {
    rehash();
  }
  sym_table->cnt++;

  string_s *sym_name = get_sym_name(sym);
  auto hash = str_hash(sym_name->str);
  auto mask = sym_table->sz - 1;

  for (size_t i = 0; i < sym_table->sz; i++) {
    auto cur = &sym_table->entries[(i + hash) & mask];
    if (*cur == 0 || *cur == TOMBSTONE ||
        strcmp(get_sym_name(to_symbol(*cur))->str, sym_name->str) == 0) {
      // Insert here.
      *cur = tag_sym(sym);
      return;
    } // Mismatched comparison, continue.
  }

  // Definitely should find a spot.
  assert(false);
}

static void rehash() {
  auto old = sym_table;
  auto new_sz = old->sz * 2;
  if (new_sz == 0) {
    new_sz = 2;
  }
  // TODO(djwatson) realloc+memset?
  sym_table = calloc(sizeof(table) + sizeof(symbol *) * new_sz, 1);
  if (!sym_table) {
    printf("symbol_table: calloc error\n");
    exit(-1);
  }
  sym_table->sz = new_sz;
  sym_table->cnt = 0;

  // Rehash items.
  for (size_t i = 0; i < old->sz; i++) {
    auto cur = &old->entries[i];
    if (*cur != 0 && *cur != TOMBSTONE) {
      symbol_table_insert_sym(to_symbol(*cur));
    }
  }

  if (old != &empty_table) {
    free(old);
  }
}

void symbol_table_clear() {
  if (sym_table != &empty_table) {
    free(sym_table);
    sym_table = &empty_table;
  }
}

gc_obj symbol_table_insert(string_s *str, bool can_alloc) {
  assert(symbol_table_find(str) == NULL);
  // Build a new symbol.
  // Must dup the string, since strings are not immutable.
  auto strlen = str->len >> 3;
  symbol *sym = NULL;
  if (can_alloc) {
    sym = GC_malloc(sizeof(symbol));
  } else {
    sym = GC_malloc_no_collect(sizeof(symbol));
    if (!sym) {
      return 0;
    }
  }

  // Note re-load of str after allocation.
  *sym = (symbol){SYMBOL_TAG, 0, tag_string(str), UNDEFINED_TAG, 0, NULL};

  // Save new symbol in frame[ra].
  gc_obj result = tag_symbol(sym);
  // DUP the string, so that this one is immutable.
  // Note that original is in sym->name temporarily
  // since ra could be eq to rb.

  string_s *str2 = NULL;
  if (can_alloc) {
    GC_push_root(&result);
    str2 = GC_malloc(16 + strlen + 1);
    GC_pop_root(&result);
  } else {
    str2 = GC_malloc_no_collect(16 + strlen + 1);
    if (!str2) {
      return 0;
    }
  }
  // Re-load sym after GC
  sym = to_symbol(result);

  *str2 = (string_s){STRING_TAG, 0, strlen << 3};
  // Re-load str after GC
  memcpy(str2->str, to_string(sym->name)->str, strlen + 1);
  sym->name = tag_string(str2);
  symbol_table_insert_sym(sym);

  return result;
}

void symbol_table_for_each(for_each_cb cb) {
  for (size_t i = 0; i < sym_table->sz; i++) {
    auto cur = &sym_table->entries[i];
    if (*cur != 0 && *cur != TOMBSTONE) {
      cb(&sym_table->entries[i]);
    }
  }
}
