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


#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)
__attribute__((noinline))
long ADDVV_SLOWPATH(long a, long b) {
  double c = (double)a + (double)b;
  c+= 1.1;
  return c;
}
int run() {
  unsigned int final_code[] = {
    CODE(CALL, 0, 0, 2),
    CODE(HALT, 0, 0, 0)
  };
  unsigned int* code = &funcs[funcs.size()-1].code[0];
    
  long*  stack = (long*)malloc(sizeof(long)*10000);
  stack[0] = (unsigned long)&final_code[1]; // return pc
  stack[1] = 40; // VALUE
  long* frame = &stack[1];

  unsigned int* pc = &code[0];
  bcfunc* func = &funcs[funcs.size()-1];

  //////////NEW:
  // if(0) {
  // unsigned int instr = *pc;
  // unsigned char op = instr & 0xff;
  // unsigned char ra = (instr >> 8) & 0xff;
  // instr >>= 16;
  // op_table[op](ARGS);
  // }

  //////////////// OLD:

  void* l_op_table[] = {NULL,
    &&L_INS_KSHORT,
    &&L_INS_ISGE,
    &&L_INS_JMP,
    &&L_INS_RET1,
    &&L_INS_SUBVN,
    &&L_INS_CALL,
    &&L_INS_ADDVV,
    &&L_INS_HALT,
  };

  //#define DIRECT {i = *pc; goto *l_op_table[INS_OP(i)];}
  #define DIRECT
  while (true) {
    unsigned int i = *pc;
     printf("Running PC %li code %s %i %i %i\n", pc - code, ins_names[INS_OP(i)], INS_A(i), INS_B(i), INS_C(i));
    // printf("%li %li \n", frame[0], frame[3]);
    
    //goto *l_op_table[INS_OP(i)];
      
    switch (INS_OP(i)) {
    case 1: {
      L_INS_KSHORT:
      //      printf("KSHORT\n");
      frame[INS_A(i)] = INS_B(i);
      pc++;
      DIRECT;
      break;
    }
    case 2: {
      L_INS_ISGE:
      //printf("ISGE\n");
      if (frame[0] >= frame[1]) {
	pc+=1;
      } else {
	pc+=2;
      }
      DIRECT;
      break;
    }
    case 3: {
      L_INS_JMP:
      //printf("JMP\n");
      pc += INS_B(i);
      DIRECT;
      break;
    }
    case 4: {
      L_INS_RET1:
      //printf("RET\n");
      pc = (unsigned int*)frame[-1];
      frame[-1] = frame[INS_A(i)];
      frame -= (INS_B(*(pc-1)) + 1);
      //printf("Frame is %x\n", frame);
      DIRECT;
      break;
    }
    case 5: {
      L_INS_SUBVN:
      //printf("SUBVN\n");
      frame[INS_A(i)] = frame[INS_B(i)] - INS_C(i);
      pc++;
      DIRECT;
      break;
    }
    case 6: {
      L_INS_CALL:
      // printf("CALL\n");
      // printf("Frame is %x\n", frame);
      frame[INS_B(i)] = (long)(pc + 1);
      pc = code;
      frame += INS_B(i) + 1;
      // printf("Frame is %x\n", frame);
      DIRECT;
      break;
    }
    case 7: {
      L_INS_ADDVV:
      //printf("ADDVV");
      auto rb = frame[INS_B(i)];
      auto rc = frame[INS_C(i)];
      if (unlikely((1UL<<63)&(rb|rc))) {
	frame[INS_A(i)] = ADDVV_SLOWPATH(rb, rc);
      } else {
	if (__builtin_add_overflow(rb, rc, &frame[INS_A(i)])) {
	  frame[INS_A(i)] = ADDVV_SLOWPATH(rb, rc);
	}
      }
      pc++;
      DIRECT;
      break;
    }
    case 8: {
      L_INS_HALT:
      printf("Result:%li\n", frame[INS_A(i)]);
      exit(0);
      break;
    }
    case 9: {
      frame[INS_A(i)] = (long)malloc(INS_B(i));
      break;
    }
    case 12: {
      L_INS_SUBVV:
      //printf("SUBVN\n");
      frame[INS_A(i)] = frame[INS_B(i)] - frame[INS_C(i)];
      pc++;
      DIRECT;
      break;
    }
    case 13: {
      L_INS_GGET:
      long* gp = (long*)func->consts[INS_A(i)];
      frame[INS_B(i)] = *gp;
      pc++;
      DIRECT;
      break;
    }
    case 14: {
      L_INS_GSET:
      long* gp = (long*)func->consts[INS_A(i)];
      *gp = frame[INS_B(i)];
      pc++;
      DIRECT;
      break;
    }

    default: {
      printf("Unknown instruction %i %s\n", INS_OP(i), ins_names[INS_OP(i)]);
      exit(-1);
    }
    }

    //assert(pc < 10);
  }
  
  return 0;
}
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
  run();
  return 0;
}
