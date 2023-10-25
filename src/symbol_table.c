// Copyright 2023 Dave Watson

#include "symbol_table.h"
#include <assert.h> // for assert
#include <stdbool.h>
#include <stdint.h> // for uint64_t
#include <stdlib.h> // for calloc, free, size_t
#include <string.h> // for strcmp

#include "third-party/cwisstable.h"

#include "defs.h"
#include "gc.h"
#include "types.h" // for string_s, symbol


typedef struct {
  uint32_t len;
  const char* str;
} StringView;

static inline size_t djb2_hash(const char *s)
{
  size_t h = 5381;
  char c;
  while ((c = *s++)) {
      h = (h << 5) + h + c;
  }
  return h;
}
static inline size_t MyMap_StringView_hash(const StringView* val) {
  return djb2_hash(val->str);
}
static inline bool MyMap_StringView_eq(const StringView* a, const gc_obj* b) {
  auto v = *(const gc_obj*)b;
  assert(is_symbol(v));
  auto sym = to_symbol(v);
  auto name = get_sym_name(sym);

  return a->len == to_fixnum(name->len) &&
    memcmp(name->str, a->str, a->len) == 0;
}
static inline size_t kCStrPolicy_hash(const void* val) {
  auto v = *(const gc_obj*)val;
  assert(is_symbol(v));
  auto sym = to_symbol(v);
  auto name = get_sym_name(sym);
  return djb2_hash(name->str);
}
static inline bool kCStrPolicy_eq(const void* a, const void* b) {
  auto va = *(const gc_obj*)a;
  assert(is_symbol(va));
  auto syma = to_symbol(va);
  auto namea = get_sym_name(syma);

  auto vb = *(const gc_obj*)b;
  assert(is_symbol(vb));
  auto symb = to_symbol(vb);
  auto nameb = get_sym_name(symb);

  return to_fixnum(namea->len) == to_fixnum(nameb->len)
    && memcmp(namea->str, nameb->str, to_fixnum(namea->len)) == 0;
}

CWISS_DECLARE_FLAT_SET_POLICY(kCStrPolicy, gc_obj,
                              (key_hash, kCStrPolicy_hash),
                              (key_eq, kCStrPolicy_eq));
CWISS_DECLARE_HASHSET_WITH(MyMap, gc_obj, kCStrPolicy);
CWISS_DECLARE_LOOKUP(MyMap, StringView);


// TODO(djwatson) weak GC syms, and evict entries when they are collected.

static MyMap sym_table;
static bool inited = false;
void sym_table_init() {
  if (!inited) {
    inited = true;
    sym_table = MyMap_new(1);
  }
}

static symbol *symbol_table_find_internal(const char *str, const uint64_t len);
symbol *symbol_table_find(string_s *str) {
  return symbol_table_find_internal(str->str, to_fixnum(str->len));
}

EXPORT symbol *symbol_table_find_cstr(const char *str) {
  return symbol_table_find_internal(str, strlen(str));
}

static symbol *symbol_table_find_internal(const char *str, const uint64_t len) {
  assert(inited);

  StringView s = {.len = len, .str = str};

  auto it = MyMap_cfind_by_StringView(&sym_table, &s);
  auto entry = MyMap_CIter_get(&it);
  if (!entry) {
    return NULL;
  }
  return to_symbol(*entry);
}

void symbol_table_clear() {
  assert(inited);
  MyMap_destroy(&sym_table);
  inited = false;
}

gc_obj symbol_table_insert(string_s *str, bool can_alloc) {
  assert(inited);

  StringView s = {.len = to_fixnum(str->len), .str = str->str};
  auto res = MyMap_deferred_insert_by_StringView(&sym_table, &s);
  auto entry = MyMap_Iter_get(&res.iter);
  if (!res.inserted) {
    return *entry;
  }

  // GC may fire below, so we need to be careful about saving str, and
  // potentially the new symbol.  We need something valid in the
  // symbol table for GC rooting, so might as well put the string
  // there.
  *entry = tag_string(str);

  // Build a new symbol.
  // Must dup the string, since strings are not immutable.
  auto strlen = to_fixnum(str->len);
  symbol *sym = NULL;
  if (can_alloc) {
    sym = GC_malloc(sizeof(symbol));
  } else {
    sym = GC_malloc_no_collect(sizeof(symbol));
    if (!sym) {
      return FALSE_REP;
    }
  }
  // Reload str after gc.
  str = to_string(*entry);

  // str now saved in sym
  *sym = (symbol){
      SYMBOL_TAG, 0,   tag_string(str), (gc_obj){.value = UNDEFINED_TAG},
      0,          NULL};

  // Save new symbol in a GC root
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
      return FALSE_REP;
    }
  }
  // Re-load sym after GC
  sym = to_symbol(result);

  *str2 = (string_s){STRING_TAG, 0, tag_fixnum(strlen)};
  // Re-load str after GC
  memcpy(str2->str, to_string(sym->name)->str, strlen + 1);
  sym->name = tag_string(str2);
  // symbol_table_insert_sym(sym);

  *entry = result;

  return result;
}

void symbol_table_for_each(for_each_cb cb) {
  assert(inited);

  auto it = MyMap_iter(&sym_table);
  auto entry = MyMap_Iter_get(&it);
  while (entry) {
    cb(entry);
    entry = MyMap_Iter_next(&it);
  }
}
