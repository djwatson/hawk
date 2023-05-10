#include <stdio.h>
#include <stdlib.h>

#include "bytecode.h"
#include "vm.h"

std::unordered_map<std::string, symbol *> symbol_table;
long* const_table;

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
  const_table = (long*)malloc(const_count * sizeof(long));
  for (unsigned j = 0; j < const_count; j++) {
    if (fread(&const_table[j], 8, 1, fptr) != 1) {
      printf("Error: Could not read consts\n");
      exit(-1);
    }
    auto type = const_table[j] & 0x7;
    if (type == 4) {
      printf("symbol: %li\n", (const_table[j] - 4) / 8);
    } else if (type == 7) {
      printf("immediate %lx\n", const_table[j]);
    } else if (type == 0){
      printf("fixnum: %li\n", const_table[j] >> 3);
    }
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
  for (int i = 0; i < const_count; i++) {
    auto&c = const_table[i];
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

void free_script() {
  for (auto &func : funcs) {
    delete func;
  }
  for (auto &s : symbol_table) {
    delete s.second;
  }
}
