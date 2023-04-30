#include <stdio.h>
#include <stdlib.h>

#include "bytecode.h"
#include "vm.h"

void readbc() {
  std::vector<std::string> symbols;

  FILE *fptr;
  fptr = fopen("out.bc", "rb");
  if (fptr == NULL) {
    printf("Could not open bc\n");
    exit(-1);
  }
  unsigned int num;
  fread(&num, 4, 1, fptr);
  printf("%.4s\n", (char *)&num);
  unsigned int version;
  fread(&version, 4, 1, fptr);
  printf("%i\n", version);
  unsigned int bccount;
  fread(&bccount, 4, 1, fptr);
  for (unsigned i = 0; i < bccount; i++) {
    bcfunc *f = new bcfunc;
    if ((((long)f) & 0x7) != 0) {
      printf("Alloc fail\n");
      exit(-1);
    }
    unsigned int const_count;
    unsigned int code_count;
    fread(&const_count, 4, 1, fptr);
    printf("%i: constsize %i \n", i, const_count);
    f->consts.resize(const_count);
    for (unsigned j = 0; j < const_count; j++) {
      if (fread(&f->consts[j], 8, 1, fptr) != 1) {
        printf("Error: Could not read consts\n");
        exit(-1);
      }
      if ((f->consts[j] & 0xf) == 4) {
        printf("symbol: %li\n", (f->consts[j] - 4) / 8);
      } else {
        printf("const: %li\n", f->consts[j] >> 3);
      }
    }
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
  for (auto &bc : funcs) {
    for (auto &c : bc->consts) {
      if ((c & 0x7) == 4) {
        std::string n(symbols[(c - 4) / 8]);
        if (symbol_table.find(n) == symbol_table.end()) {
          symbol_table[n] = new symbol{n, UNDEFINED};
        }
        c = (unsigned long)symbol_table[n];
        printf("Link global %s %lx\n", n.c_str(), c);
      }
    }
  }
}
