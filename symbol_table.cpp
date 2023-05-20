#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "symbol_table.h"

void*GC_malloc(size_t);
void GC_free(void* ptr) {
}


/* FNV-1a */
uint64_t str_hash(const char* str) {
  auto p = str;
  uint64_t hash = 0xcbf29ce484222325;

  while(*p++) {
    hash ^= *p;
    hash *= 0x100000001b3;
  }

  return hash;
}

// string_s* to symbol* hash table.
// Size must be power of two.
// Bottom bits may be tombstone.
// Open coded.

// TODO weak GC syms, and evict entries when they are collected.  Somehow.

#define TOMBSTONE ((string_s*)0x01)

struct table_entry {
  string_s* str;
  symbol* sym;
};

struct table {
  size_t cnt; // Number of objects currently in hash.
  size_t sz; // Size of backing buffer.

  table_entry entries[];
};

// Non-empty default table so we don't have to null check.
static table empty_table{0,0};
static table* sym_table = &empty_table;

symbol* symbol_table_find(string_s* str) {
  auto hash = str_hash(str->str);

  auto mask = sym_table->sz-1;
  for(size_t i = 0; i < sym_table->sz; i++) {
    auto cur = &sym_table->entries[(i+hash)&mask];
    if (cur->str == nullptr) {
      return nullptr;
    } else if (cur->str == TOMBSTONE) {
      continue;
    } else if (strcmp(cur->str->str, str->str) == 0) {
      return cur->sym;
    } else {
      // Mismatched comparison, continue.
      continue;
    }
  }

  return nullptr;
}

static void rehash();
void symbol_table_insert(string_s* str, symbol* sym) {
  sym_table->cnt++;
  if (sym_table->cnt > (sym_table->sz / 2)) {
    rehash();
  }
  auto hash = str_hash(str->str);
  auto mask = sym_table->sz-1;
  for(size_t i = 0; i < sym_table->sz; i++) {
    auto cur = &sym_table->entries[(i+hash)&mask];
    if (cur->str == nullptr || cur->str == TOMBSTONE || strcmp(cur->str->str, str->str) == 0) {
      // Insert here.
      cur->str = str;
      cur->sym = sym;
      return;
    } else {
      // Mismatched comparison, continue.
      continue;
    }
  }

  // Definitely should find a spot.
  assert(false);
}

static void rehash() {
  auto old = sym_table;
  auto new_sz = old->cnt*4;
  sym_table = (table*)GC_malloc(sizeof (table) + sizeof(table_entry) * new_sz);
  sym_table->sz = new_sz;
  sym_table->cnt = 0;

  // Rehash items.
  for(size_t i = 0; i < old->sz; i++) {
    auto cur = &old->entries[i];
    if (cur->str != nullptr &&
	cur->str != TOMBSTONE) {
      symbol_table_insert(cur->str, cur->sym);
    }
  }

  GC_free(old);
}

