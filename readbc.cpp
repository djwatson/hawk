#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <unordered_map>
#include <string>

enum {
  RET=0,
  KSHORT,
  ISGE,
  JMP,
  RET1,
  SUBVN,
  CALL,
  ADDVV,
  HALT,
  ALLOC,
  ISLT,
  ISF,
  SUBVV,
  GGET,
  GSET,
  KFUNC,
  CALLT,
};

const char* ins_names[] = {
  "RET",
  "KSHORT",
  "ISGE",
  "JMP",
  "RET1",
  "SUBVN",
  "CALL",
  "ADDVV",
  "HALT",
  "ALLOC",
  "ISLT",
  "ISF",
  "SUBVV",
  "GGET",
  "GSET",
  "KFUNC",
  "CALLT",
};

/*
 (if (< n 2)
     n
     (+ (recursive (- n 1))
        (recursive (- n 2))))
 */
#define CODE(i,a,b,c) ((c << 24) | (b << 16) | (a << 8) | i)
#define INS_OP(i) (i&0xff)
#define INS_A(i) ((i>>8)&0xff)
#define INS_B(i) ((i>>16)&0xff)
#define INS_C(i) ((i>>24)&0xff)

struct bcfunc {
  std::vector<unsigned int> code;
  std::vector<unsigned long> consts;
};

struct symbol {
  std::string name;
  unsigned long val;
};

std::vector<std::string> symbols;
std::vector<bcfunc> funcs;
std::unordered_map<std::string, symbol*> symbol_table;

int main() {
  FILE *fptr;
  fptr = fopen("out.bc", "rb");
  if (fptr == NULL) {
    printf("Could not open bc\n");
    exit(-1);
  }
  unsigned int num;
  fread(&num, 4, 1, fptr);
  printf("%.4s\n", (char*)&num);
  unsigned int version;
  fread(&version, 4, 1, fptr);
  printf("%i\n", version);
  unsigned int bccount;
  fread(&bccount, 4, 1, fptr);
  for(unsigned i = 0; i < bccount; i++) {
    bcfunc f;
    unsigned int const_count;
    unsigned int code_count;
    fread(&const_count, 4, 1, fptr);
    f.consts.resize(const_count);
    for(unsigned j = 0; j < const_count; j++) {
      f.consts[j] = 0;
      fread(&f.consts[j], 4, 1, fptr);
      printf("const: %li\n", (f.consts[j]-4)/8);
    }
    fread(&code_count, 4, 1, fptr);
    f.code.resize(code_count);
    for(unsigned j = 0; j < code_count; j++) {
      fread(&f.code[j], 4, 1, fptr);
      unsigned int code = f.code[j];
      printf("code: %s %i %i %i\n", 
	     ins_names[INS_OP(code)],
	     INS_A(code),
	     INS_B(code),
	     INS_C(code));
    }
    printf("%i: const %i code %i\n", i, const_count, code_count);
    funcs.push_back(f);
  }
  unsigned int g_count;
  fread(&g_count, 4, 1, fptr);
  printf("GLobals: %i\n", g_count);
  for(unsigned i = 0; i < g_count; i++) {
    unsigned int len;
    fread(&len, 4, 1, fptr);
    std::string name;
    name.resize(len+1);
    fread(&name[0], 1, len, fptr);
    name[len] = '\0';
    printf("Global: %s\n", name.c_str());
    symbols.push_back(name);
  }
  
  fclose(fptr);
  // Link the symbols
  for(auto &bc : funcs) {
    for(auto &c : bc.consts) {
      std::string n = symbols[(c - 4)/8];
      if (symbol_table.find(n) == symbol_table.end()) {
	symbol_table[n] = new symbol;
      }
      c = (unsigned long)&symbol_table[n]->val;
    }
  }
  return 0;
}
