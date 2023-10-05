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

#define auto __auto_type
#define nullptr NULL

long *const_table = nullptr;
unsigned long const_table_sz = 0;
long *symbols = NULL; // TODO not a global, or use a string instead

// TODO GC safety
long read_const(FILE *fptr) {
  long val;
  if (fread(&val, 1, 8, fptr) != 8) {
    goto error;
  }
  auto type = val & TAG_MASK;
  if (type == SYMBOL_TAG) {
    unsigned long num = val >> 3;
    if (num < arrlen(symbols)) {
      val = symbols[num];
    } else {
      // It's a new symbol in this bc file
      long len;
      if (8 != fread(&len, 1, 8, fptr)) {
	goto error;
      }
      // TODO GC symbol table
      auto str = (string_s *)GC_malloc(16 + 1 + len);
      str->type = STRING_TAG;
      str->len = len << 3;
      str->str[len] = '\0';
      str->rc = 0;
      if (fread(str->str, 1, len, fptr) != len) {
	goto error;
      }

      // Try to see if it already exists
      auto res = symbol_table_find(str);
      if (res == nullptr) {
        long str_save = (long)str + PTR_TAG;
        GC_push_root(&str_save);
        // TODO GC symbol table
        auto sym = (symbol *)GC_malloc(sizeof(symbol));

        GC_pop_root(&str_save);
        str = (string_s *)(str_save - PTR_TAG);

        sym->type = SYMBOL_TAG;
        sym->name = (long)str + PTR_TAG;
        sym->val = UNDEFINED_TAG;
        sym->opt = 0;
        sym->lst = NULL;
        sym->rc = 0;
        symbol_table_insert(sym);
        val = (long)sym | SYMBOL_TAG;
        arrput(symbols, val);
      } else {
        val = (long)res + SYMBOL_TAG;
        arrput(symbols, val);
        return val;
      }
    }
  } else if (type == LITERAL_TAG || type == FIXNUM_TAG) {
  } else if (type == FLONUM_TAG) {
    auto f = (flonum_s *)GC_malloc(sizeof(flonum_s));
    assert(!((long)f & TAG_MASK));
    if (fread(&f->x, 1, 8, fptr) != 8) {
      goto error;
    }
    f->type = FLONUM_TAG;
    f->rc = 0;
    val = (long)f | FLONUM_TAG;
  } else if (type == CONS_TAG) {
    auto ca = read_const(fptr);
    GC_push_root(&ca);
    auto cb = read_const(fptr);
    GC_push_root(&cb);

    auto c = (cons_s *)GC_malloc(sizeof(cons_s));
    c->type = CONS_TAG;
    c->a = ca;
    c->rc = 0;
    c->b = cb;
    GC_pop_root(&cb);
    GC_pop_root(&ca);

    val = (long)c | CONS_TAG;
  } else if (type == PTR_TAG) {
    long ptrtype;
    if (fread(&ptrtype, 1, 8, fptr) != 8) {
      goto error;
    }
    if (ptrtype == STRING_TAG) {
      long len;
      if (fread(&len, 1, 8, fptr) != 8) {
	goto error;
      }
      auto str = (string_s *)GC_malloc(16 + len + 1);
      str->type = ptrtype;
      str->len = len << 3;
      str->rc = 0;
      if (fread(&str->str, 1, len, fptr) != len) {
	goto error;
      }
      str->str[len] = '\0';
      val = (long)str | PTR_TAG;
    } else if (ptrtype == VECTOR_TAG) {
      long len;
      if (fread(&len, 1, 8, fptr) != 8) {
	goto error;
      }

      long *vals = malloc(sizeof(long) * len);
      assert(vals);
      for (long i = 0; i < len; i++) {
        vals[i] = read_const(fptr);
        GC_push_root(&vals[i]);
      }

      auto v = (vector_s *)GC_malloc(16 + len * sizeof(long));
      v->type = ptrtype;
      v->len = len << 3;
      v->rc = 0;
      for (long i = len - 1; i >= 0; i--) {
        v->v[i] = vals[i];
        GC_pop_root(&vals[i]);
      }
      free(vals);
      val = (long)v | PTR_TAG;
    } else {
      printf("Unknown boxed type:%lx\\n", ptrtype);
      exit(-1);
    }
  } else {
    printf("Unknown deserialize tag %lx\n", val);
    exit(-1);
  }
  return val;
 error:
  printf("Error: Could not read consts\n");
  exit(-1);
}

bcfunc *readbc(FILE *fptr) {
  unsigned long const_offset = const_table_sz;
  arrfree(symbols);

  if (fptr == nullptr) {
    printf("Could not open bc\n");
    exit(-1);
  }
  // Read header
  unsigned int num;
  if (fread(&num, 1, 4, fptr) != 4) {
    goto error;
  }
  // printf("%.4s\n", (char *)&num);
  if (num != 0x4d4f4f42) { // MAGIC
    printf("Error: not a hawk bitcode\n");
    exit(-1);
  }
  unsigned int version;
  if (fread(&version, 1, 4, fptr) != 4) {
    goto error;
  }
  if (version != 0) {
    printf("Invalid bitcode version: %i\n", version);
    exit(-1);
  }
  // printf("%i\n", version);

  // Read constant table
  unsigned int const_count;
  if (fread(&const_count, 1, 4, fptr) != 4) {
    goto error;
  }
  // printf("constsize %i \n", const_count);
  const_table =
      (long *)realloc(const_table, (const_count + const_offset) * sizeof(long));
  if (!const_table) {
    printf("Error: Could not realloc const_table\n");
    exit(-1);
  }
  // Memset new entries in case we get GC during file read.
  memset(&const_table[const_table_sz], 0, sizeof(long) * const_count);
  const_table_sz += const_count;
  if (const_table_sz >= 65536) {
    printf("ERROR const table too big! %li\n", const_table_sz);
    exit(-1);
  }
  for (unsigned j = 0; j < const_count; j++) {
    const_table[j + const_offset] = read_const(fptr);
    // printf("%i: ", j);
    // print_obj(const_table[j]);
    // printf("\n");
  }

  // Read functions
  unsigned int bccount;
  if (fread(&bccount, 1, 4, fptr) != 4) {
    goto error;
  }
  bcfunc *start_func = nullptr;
  unsigned func_offset = arrlen(funcs);
  for (unsigned i = 0; i < bccount; i++) {
    unsigned int name_count;
    if (fread(&name_count, 1, 4, fptr) != 4) {
      goto error;
    }
    // printf("Name size %i\n", name_count);
    char *name = (char *)malloc(name_count + 1);
    assert(name);
    name[name_count] = '\0';
    if (fread(name, 1, name_count, fptr) != name_count) {
      goto error;
    }

    unsigned int code_count;
    if (fread(&code_count, 1, 4, fptr) != 4) {
      goto error;
    }

    auto f =
        (bcfunc *)malloc(sizeof(bcfunc) + sizeof(unsigned int) * code_count);
    if (start_func == nullptr) {
      start_func = f;
    }
    if ((((long)f) & 0x7) != 0) {
      printf("Alloc fail\n");
      exit(-1);
    }
    f->name = name;
    f->codelen = code_count;
    f->poly_cnt = 0;

    // printf("%i: code %i\n", i, code_count);
    for (unsigned j = 0; j < code_count; j++) {
      if(fread(&f->code[j], 1, 4, fptr) != 4) {
	goto error;
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

  fclose(fptr);
  return start_func;
 error:
  printf("Could not parse bc file\n");
  exit(-1);
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
  // TODO symbol_table
  free(const_table);
  const_table = NULL;
  symbol_table_clear();
}

/* extern unsigned char bootstrap_scm_bc[]; */
/* extern unsigned int bootstrap_scm_bc_len; */

EXPORT void load_bootstrap() {
  /* if (bootstrap_scm_bc_len > 0) { */
  /*   auto start_func = readbc_image(bootstrap_scm_bc, bootstrap_scm_bc_len); */
  /*   // printf("Running boot image...\n"); */
  /*   run(start_func, 0, nullptr); */
  /* } */
}
