#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <gc/gc.h>

#include "bytecode.h"
#include "vm.h"
#include "types.h"

std::unordered_map<std::string, symbol *> symbol_table;
long* const_table;

long read_const(FILE* fptr) {
  long val;
  if (fread(&val, 8, 1, fptr) != 1) {
    printf("Error: Could not read consts\n");
    exit(-1);
  }
  auto type = val & 0x7;
  if (type == 4) {
    printf("symbol: %li\n", (val - 4) / 8);
  } else if (type == 7) {
    printf("immediate %lx\n", val);
  } else if (type == FIXNUM_TAG){
    printf("fixnum: %li\n", val >> 3);
  } else if (type == FLONUM_TAG) {
    auto f = (flonum_s*)GC_malloc(sizeof(flonum_s));
    assert(!((long)f&TAG_MASK));
    fread(&f->x, 8, 1, fptr);
    printf("Flonum: %f\n", f->x);
    val = (long)f | FLONUM_TAG;
  } else if (type == CONS_TAG) {
    auto c = (cons_s*)GC_malloc(sizeof(cons_s));
    c->a = read_const(fptr);
    c->b = read_const(fptr);
    val = (long)c | CONS_TAG;
  } else if (type == PTR_TAG) {
    long ptrtype;
    fread(&ptrtype, 8, 1, fptr);
    if (ptrtype == STRING_TAG) {
      long len;
      fread(&len, 8, 1, fptr);
      auto str = (string_s*)GC_malloc(16 + len + 1);
      str->type = ptrtype;
      str->len = len;
      fread(&str->str, 1, len, fptr);
      str->str[len] = '\0';
      printf("String %s\n", str->str);
      val = (long)str|PTR_TAG;
    } else if (ptrtype == VECTOR_TAG) {
      long len;
      fread(&len, 8, 1, fptr);
      auto v = (vector_s*)GC_malloc(16 + len*sizeof(long));
      v->type = ptrtype;
      v->len = len;
      for(long i = 0; i < len; i++) {
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
  std::vector<std::string> symbols;

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
  const_table = (long*)GC_malloc(const_count * sizeof(long));
  for (unsigned j = 0; j < const_count; j++) {
    const_table[j] = read_const(fptr);
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
    unsigned int code_count;
    fread(&code_count, 4, 1, fptr);
    f->code.resize(code_count);
    printf("%i: code %i\n", i, code_count);
    for (unsigned j = 0; j < code_count; j++) {
      fread(&f->code[j], 4, 1, fptr);
      unsigned int code = f->code[j];
      printf("%i code: %s %i %i %i BC: %i\n", j, ins_names[INS_OP(code)],
             INS_A(code), INS_B(code), INS_C(code), INS_BC(code));
    }
    funcs.push_back(f);
  }
  unsigned int g_count;
  fread(&g_count, 4, 1, fptr);
  printf("GLobals: %i\n", g_count);
  for (unsigned i = 0; i < g_count; i++) {
    unsigned int len;
    fread(&len, 4, 1, fptr);
    std::string name;
    name.resize(len + 1);
    fread(&name[0], 1, len, fptr);
    name[len] = '\0';
    printf("Global: %s\n", name.c_str());
    symbols.push_back(name);
  }

  fclose(fptr);
  // Link the symbols
  for (unsigned i = 0; i < const_count; i++) {
    auto&c = const_table[i];
    if ((c & 0x7) == 4) {
      std::string n(symbols[(c - 4) / 8]);
      if (symbol_table.find(n) == symbol_table.end()) {
	auto len = strlen(n.c_str());
	auto str = (string_s*)GC_malloc(16 + 1 + len);
	str->type = STRING_TAG;
	str->len = len;
	str->str[len] = '\0';
	memcpy(str->str, &n[0], str->len);
	auto sym = (symbol*)GC_malloc(sizeof(symbol));
	sym->name = str;
	sym->val = UNDEFINED_TAG;
	symbol_table[n] = sym;
      }
      c = (unsigned long)symbol_table[n]|SYMBOL_TAG;
      printf("Link global %s %lx\n", n.c_str(), c);
    }
  }
}

void free_script() {
  for (auto &func : funcs) {
    delete func;
  }
  // TODO symbol_table
}
