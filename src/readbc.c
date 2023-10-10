// Copyright 2023 Dave Watson

#include "readbc.h"

#include <assert.h> // for assert
#include <stdint.h> // for uint64_t
#include <stdio.h>  // for fread, printf, FILE, fclose, fmemopen, fopen
#include <stdlib.h> // for exit, realloc
#include <string.h> // for memset

#include "bytecode.h" // for bcfunc, CODE_D, INS_A, INS_D, INS_OP
#include "defs.h"
#include "gc.h"           // for GC_malloc, GC_pop_root, GC_push_root
#include "opcodes.h"      // for GGET, GSET, KFUNC, KONST
#include "symbol_table.h" // for symbol_table_find, symbol_table_insert
#include "third-party/stb_ds.h"
#include "types.h" // for string_s, PTR_TAG, SYMBOL_TAG, cons_s, symbol
#include "vm.h"    // for funcs

gc_obj *const_table = nullptr;
uint64_t const_table_sz = 0;
// TODO(djwatson) not a global, or use a string instead
gc_obj *symbols = NULL;

static gc_obj read_const(FILE *fptr);

static void read_error() {
  printf("Error: Could not read consts\n");
  exit(-1);
}

static gc_obj read_symbol(FILE *fptr, uint64_t num) {
  if (num < arrlen(symbols)) {
    return symbols[num];
  }
  // It's a new symbol in this bc file
  uint64_t len;
  if (8 != fread(&len, 1, 8, fptr)) {
    read_error();
  }
  string_s *str = GC_malloc(16 + 1 + len);
  *str = (string_s){STRING_TAG, 0, len << 3};
  if (fread(str->str, 1, len, fptr) != len) {
    read_error();
  }
  str->str[len] = '\0';

  // TODO(djwatson) this could be merged with string->symbol
  // Don't need to malloc string first
  // Try to see if it already exists
  auto res = symbol_table_find(str);
  if (res == nullptr) {
    gc_obj str_save = tag_string(str);
    GC_push_root(&str_save);
    symbol *sym = GC_malloc(sizeof(symbol));

    GC_pop_root(&str_save);
    *sym = (symbol){SYMBOL_TAG, 0, str_save, UNDEFINED_TAG, 0, NULL};

    symbol_table_insert(sym);
    gc_obj val = tag_symbol(sym);
    arrput(symbols, val);
    return val;
  }

  gc_obj val = tag_symbol(res);
  arrput(symbols, val);
  return val;
}

static gc_obj read_flonum(FILE *fptr) {
  flonum_s *f = GC_malloc(sizeof(flonum_s));
  if (fread(&f->x, 1, 8, fptr) != 8) {
    read_error();
  }
  f->type = FLONUM_TAG;
  f->rc = 0;
  return tag_flonum(f);
}

static gc_obj read_cons(FILE *fptr) {
  auto ca = read_const(fptr);
  GC_push_root(&ca);
  auto cb = read_const(fptr);
  GC_push_root(&cb);

  cons_s *c = GC_malloc(sizeof(cons_s));
  c->type = CONS_TAG;
  c->a = ca;
  c->rc = 0;
  c->b = cb;
  GC_pop_root(&cb);
  GC_pop_root(&ca);

  return tag_cons(c);
}

static gc_obj read_ptr(FILE *fptr) {
  uint64_t ptrtype;
  if (fread(&ptrtype, 1, 8, fptr) != 8) {
    read_error();
  }
  if (ptrtype == STRING_TAG) {
    uint64_t len;
    if (fread(&len, 1, 8, fptr) != 8) {
      read_error();
    }
    string_s *str = GC_malloc(16 + len + 1);
    str->type = ptrtype;
    str->len = len << 3;
    str->rc = 0;
    if (fread(&str->str, 1, len, fptr) != len) {
      read_error();
    }
    str->str[len] = '\0';
    return tag_string(str);
  }
  read_error();
  __builtin_unreachable();
}

static gc_obj read_vector(FILE *fptr) {
  uint64_t len;
  if (fread(&len, 1, 8, fptr) != 8) {
    read_error();
  }

  gc_obj *vals = malloc(sizeof(gc_obj) * len);
  assert(vals);
  for (uint64_t i = 0; i < len; i++) {
    vals[i] = read_const(fptr);
    GC_push_root(&vals[i]);
  }

  vector_s *v = GC_malloc(16 + len * sizeof(gc_obj));
  v->type = VECTOR_TAG;
  v->len = len << 3;
  v->rc = 0;
  for (int64_t i = len - 1; i >= 0; i--) {
    v->v[i] = vals[i];
    GC_pop_root(&vals[i]);
  }
  free(vals);
  return tag_vector(v);
}

static gc_obj read_closure(FILE *fptr) {
  uint64_t bcfunc_num;
  if (fread(&bcfunc_num, 1, 8, fptr) != 8) {
    read_error();
  }
  closure_s *clo = GC_malloc(sizeof(closure_s) + 8);
  clo->type = CLOSURE_TAG;
  clo->rc = 0;
  clo->len = 1 << 3;
  clo->v[0] = bcfunc_num << 3; // Updated below.
  return tag_closure(clo);
}

static gc_obj read_const(FILE *fptr) {
  gc_obj val;
  if (fread(&val, 1, 8, fptr) != 8) {
    read_error();
  }
  auto type = val & TAG_MASK;
  if (type == SYMBOL_TAG) {
    return read_symbol(fptr, val >> 3);
  } else if (type == FLONUM_TAG) {
    return read_flonum(fptr);
  } else if (type == CONS_TAG) {
    return read_cons(fptr);
  } else if (type == PTR_TAG) {
    return read_ptr(fptr);
  } else if (type == VECTOR_TAG) {
    return read_vector(fptr);
  } else if (type == CLOSURE_TAG) {
    return read_closure(fptr);
  }

  // Fallthrough for literals and fixnum.
  return val;
}

static void parse_error() {
  printf("Could not parse bc file\n");
  exit(-1);
}

bcfunc *readbc(FILE *fptr) {
  auto const_offset = const_table_sz;
  arrfree(symbols);

  if (fptr == nullptr) {
    printf("Could not open bc\n");
    exit(-1);
  }
  // Read header
  uint32_t num;
  if (fread(&num, 1, 4, fptr) != 4) {
    parse_error();
  }
  // printf("%.4s\n", (char *)&num);
  if (num != 0x4d4f4f42) { // MAGIC
    printf("Error: not a hawk bitcode\n");
    exit(-1);
  }
  uint32_t version;
  if (fread(&version, 1, 4, fptr) != 4) {
    parse_error();
  }
  if (version != 0) {
    printf("Invalid bitcode version: %u\n", version);
    exit(-1);
  }
  // printf("%i\n", version);

  // Read constant table
  uint32_t const_count;
  if (fread(&const_count, 1, 4, fptr) != 4) {
    parse_error();
  }
  // printf("constsize %i \n", const_count);
  const_table =
      realloc(const_table, (const_count + const_offset) * sizeof(gc_obj));
  if (!const_table) {
    printf("Error: Could not realloc const_table\n");
    exit(-1);
  }
  // Memset new entries in case we get GC during file read.
  memset(&const_table[const_table_sz], 0, sizeof(gc_obj) * const_count);
  const_table_sz += const_count;
  if (const_table_sz >= 65536) {
    printf("ERROR const table too big! %lu\n", const_table_sz);
    exit(-1);
  }
  for (uint32_t j = 0; j < const_count; j++) {
    const_table[j + const_offset] = read_const(fptr);
    // printf("%i: %i", j, const_table[j]&TAG_MASK);
    // print_obj(const_table[j], stdout);
    // printf("\n");
  }

  // Read functions
  uint32_t bccount;
  if (fread(&bccount, 1, 4, fptr) != 4) {
    parse_error();
  }
  bcfunc *start_func = nullptr;
  uint64_t func_offset = arrlen(funcs);
  for (uint32_t i = 0; i < bccount; i++) {
    uint32_t name_count;
    if (fread(&name_count, 1, 4, fptr) != 4) {
      parse_error();
    }
    // printf("Name size %i\n", name_count);
    char *name = malloc(name_count + 1);
    assert(name);
    name[name_count] = '\0';
    if (fread(name, 1, name_count, fptr) != name_count) {
      parse_error();
    }

    uint32_t code_count;
    if (fread(&code_count, 1, 4, fptr) != 4) {
      parse_error();
    }

    bcfunc *f = malloc(sizeof(bcfunc) + sizeof(uint32_t) * code_count);
    if (start_func == nullptr) {
      start_func = f;
    }
    f->name = name;
    f->codelen = code_count;
    f->poly_cnt = 0;

    // printf("%i: code %i\n", i, code_count);
    for (uint32_t j = 0; j < code_count; j++) {
      if (fread(&f->code[j], 1, 4, fptr) != 4) {
        parse_error();
      }
      // Need to update anything pointing to global const_table
      auto op = INS_OP(f->code[j]);
      if (op == GGET || op == GSET || op == KONST) {
        f->code[j] =
            CODE_D(op, INS_A(f->code[j]), INS_D(f->code[j]) + const_offset);
      } else if (op == KFUNC) {
        f->code[j] =
            CODE_D(op, INS_A(f->code[j]), INS_D(f->code[j]) + func_offset);
      }
      // unsigned int code = f->code[j];
      //  printf("%i code: %s %i %i %i BC: %i\n", j, ins_names[INS_OP(code)],
      //         INS_A(code), INS_B(code), INS_C(code), INS_BC(code));
    }
    arrput(funcs, f);
  }
  // Update any new constant closures.
  for (uint64_t i = const_offset; i < const_table_sz; i++) {
    auto v = const_table[i];
    if (is_closure(v)) {
      auto clo = to_closure(v);
      clo->v[0] = (long)funcs[func_offset + (clo->v[0] >> 3)];
    }
  }

  fclose(fptr);
  return start_func;
}

EXPORT bcfunc *readbc_image(unsigned char *mem, unsigned int len) {
  FILE *fptr = fmemopen(mem, len, "rb");
  return readbc(fptr);
}

EXPORT bcfunc *readbc_file(const char *filename) {
  FILE *fptr;
  fptr = fopen(filename, "rb");
  return readbc(fptr);
}

EXPORT void free_script() {
  for (uint64_t i = 0; i < arrlen(funcs); i++) {
    auto func = funcs[i];
    free(func->name);
    func->name = NULL;
    free(func);
  }
  arrfree(funcs);
  arrfree(symbols);
  free(const_table);
  const_table = NULL;
  symbol_table_clear();
}

extern unsigned char bootstrap_scm_bc[];
extern unsigned int bootstrap_scm_bc_len;

EXPORT void load_bootstrap() {
  if (bootstrap_scm_bc_len > 0) {
    auto start_func = readbc_image(bootstrap_scm_bc, bootstrap_scm_bc_len);
    // printf("Running boot image...\n");
    run(start_func, 0, nullptr);
  }
}
