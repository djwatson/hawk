#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gc/gc.h>

#include "bytecode.h"
#include "types.h"
#include "vm.h"

std::unordered_map<std::string, symbol *> symbol_table;
long *const_table;
static std::vector<long> symbols; // TODO not a global

long read_const(FILE *fptr) {
  long val;
  if (fread(&val, 8, 1, fptr) != 1) {
    printf("Error: Could not read consts\n");
    exit(-1);
  }
  auto type = val & 0x7;
  if (type == 4) {
    unsigned long num = val >> 3;
    if (num < symbols.size()) {
      val = symbols[num];
    } else {
      // It's a new symbol
      long len;
      fread(&len, 8, 1, fptr);
      // TODO GC symbol table
      auto str = (string_s *)GC_malloc(16 + 1 + len);
      str->type = STRING_TAG;
      str->len = len;
      str->str[len] = '\0';
      fread(str->str, 1, len, fptr);
      // TODO GC symbol table
      auto sym = (symbol *)GC_malloc(sizeof(symbol));
      sym->name = str;
      sym->val = UNDEFINED_TAG;
      symbol_table[std::string(str->str)] = sym;
      val = (long)sym | SYMBOL_TAG;
      symbols.push_back(val);
    }
  } else if (type == 7) {
  } else if (type == FIXNUM_TAG) {
  } else if (type == FLONUM_TAG) {
    auto f = (flonum_s *)GC_malloc(sizeof(flonum_s));
    assert(!((long)f & TAG_MASK));
    fread(&f->x, 8, 1, fptr);
    val = (long)f | FLONUM_TAG;
  } else if (type == CONS_TAG) {
    auto c = (cons_s *)GC_malloc(sizeof(cons_s));
    c->a = read_const(fptr);
    c->b = read_const(fptr);
    val = (long)c | CONS_TAG;
  } else if (type == PTR_TAG) {
    long ptrtype;
    fread(&ptrtype, 8, 1, fptr);
    if (ptrtype == STRING_TAG) {
      long len;
      fread(&len, 8, 1, fptr);
      auto str = (string_s *)GC_malloc(16 + len + 1);
      str->type = ptrtype;
      str->len = len;
      fread(&str->str, 1, len, fptr);
      str->str[len] = '\0';
      val = (long)str | PTR_TAG;
    } else if (ptrtype == VECTOR_TAG) {
      long len;
      fread(&len, 8, 1, fptr);
      auto v = (vector_s *)GC_malloc(16 + len * sizeof(long));
      v->type = ptrtype;
      v->len = len;
      for (long i = 0; i < len; i++) {
        v->v[i] = read_const(fptr);
      }
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
}

void readbc() {

  FILE *fptr;
  fptr = fopen("out.bc", "rb");
  if (fptr == NULL) {
    printf("Could not open bc\n");
    exit(-1);
  }
  // Read header
  unsigned int num;
  fread(&num, 4, 1, fptr);
  printf("%.4s\n", (char *)&num);
  unsigned int version;
  fread(&version, 4, 1, fptr);
  printf("%i\n", version);

  // Read constant table
  unsigned int const_count;
  fread(&const_count, 4, 1, fptr);
  printf("constsize %i \n", const_count);
  const_table = (long *)GC_malloc(const_count * sizeof(long));
  for (unsigned j = 0; j < const_count; j++) {
    const_table[j] = read_const(fptr);
    // printf("%i: ", j);
    // print_obj(const_table[j]);
    // printf("\n");
  }

  // Read functions
  unsigned int bccount;
  fread(&bccount, 4, 1, fptr);
  for (unsigned i = 0; i < bccount; i++) {
    bcfunc *f = new bcfunc;
    if ((((long)f) & 0x7) != 0) {
      printf("Alloc fail\n");
      exit(-1);
    }
    unsigned int name_count;
    fread(&name_count, 4, 1, fptr);
    f->name.resize(name_count + 1);
    f->name[name_count] = '\0';
    //printf("Name size %i\n", name_count);
    fread(&f->name[0], 1, name_count, fptr);
    
    unsigned int code_count;
    fread(&code_count, 4, 1, fptr);
    f->code.resize(code_count);
    //printf("%i: code %i\n", i, code_count);
    for (unsigned j = 0; j < code_count; j++) {
      fread(&f->code[j], 4, 1, fptr);
      //unsigned int code = f->code[j];
      // printf("%i code: %s %i %i %i BC: %i\n", j, ins_names[INS_OP(code)],
      //        INS_A(code), INS_B(code), INS_C(code), INS_BC(code));
    }
    funcs.push_back(f);
  }

  fclose(fptr);
}

void free_script() {
  for (auto &func : funcs) {
    delete func;
  }
  // TODO symbol_table
}
