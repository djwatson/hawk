#include "bytecode.h"
#include "vm.h"

std::vector<bcfunc*> funcs;
std::unordered_map<std::string, symbol*> symbol_table;


#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)
__attribute__((noinline))
long ADDVV_SLOWPATH(long a, long b) {
  double c = (double)a + (double)b;
  c+= 1.1;
  return c;
}
__attribute__((noinline))
long FAIL_SLOWPATH(long a, long b) {
  printf("FAIL not an int\n");
  exit(-1);
  return a;
}
__attribute__((noinline))
void UNDEFINED_SYMBOL_SLOWPATH(symbol* s) {
  printf("FAIL undefined symbol: %s\n", s->name.c_str());
  exit(-1);
}
__attribute__((noinline))
void HOTMAP_SLOWPATH(unsigned int* pc, unsigned long f) {
  bcfunc* func = (bcfunc*)f;
  //printf("Hotmap hit pc %li\n", pc - &func->code[0]);
}
unsigned int stacksz = 1000;
long*  stack = (long*)malloc(sizeof(long)*stacksz);
__attribute__((noinline))
void EXPAND_STACK_SLOWPATH() {
  printf("Expand stack from %i to %i\n", stacksz, stacksz*2);
  stacksz *= 2;
  stack = (long*)realloc(stack, stacksz * sizeof(long));
}

void run() {
  unsigned int final_code[] = {
    CODE(CALL, 0, 1, 0),
    CODE(HALT, 0, 0, 0)
  };
  unsigned int* code = &funcs[0]->code[0];
    
  stack[0] = (unsigned long)&final_code[1]; // return pc
  stack[1] = (unsigned long)funcs[0]; // func
  long* frame = &stack[2];
  long* frame_top = stack + stacksz;

  unsigned int* pc = &code[0];

  unsigned char hotmap[hotmap_sz];
  for(int i = 0; i < hotmap_sz; i++) {
    hotmap[i] = hotmap_cnt;
  }

  void* l_op_table[] = {
    NULL,
    &&L_INS_KSHORT,
    &&L_INS_ISGE,
    &&L_INS_JMP,
    &&L_INS_RET1,
    &&L_INS_SUBVN,
    &&L_INS_CALL,
    &&L_INS_ADDVV,
    &&L_INS_HALT,
    &&L_INS_ALLOC,
    &&L_INS_ISLT, //10
    &&L_INS_ISF,
    &&L_INS_SUBVV,
    &&L_INS_GGET,
    &&L_INS_GSET,
    &&L_INS_KFUNC,
    &&L_INS_CALLT,
    &&L_INS_KONST,
    &&L_INS_MOV,
    &&L_INS_ISEQ,
    &&L_INS_ADDVN, //20
    &&L_INS_JISEQ,
    &&L_INS_JISLT,
  };

  //#define DIRECT {i = *pc; goto *l_op_table[INS_OP(i)];}
#define DIRECT
  while (true) {
    unsigned int i = *pc;
#ifdef DEBUG
     printf("Running PC %li code %s %i %i %i\n", pc - code, ins_names[INS_OP(i)], INS_A(i), INS_B(i), INS_C(i));
     printf("frame %li: %li %li %li %li\n", frame-stack, frame[0], frame[1], frame[2], frame[3]);
#else
    
    goto *l_op_table[INS_OP(i)];
    #endif
      
    switch (INS_OP(i)) {
    case 1: {
      L_INS_KSHORT:
      frame[INS_A(i)] = INS_BC(i) << 3;
      pc++;
      DIRECT;
      break;
    }
    case 2: {
      L_INS_ISGE:
      long fa = frame[INS_A(i)];
      long fb = frame[INS_B(i)];
      if (unlikely(1&(fa | fb))) {
	FAIL_SLOWPATH(fa, fb);
      }
      if (fa >= fb) {
	pc+=1;
      } else {
	pc+=2;
      }
      DIRECT;
      break;
    }
    case 21: {
      L_INS_JISEQ:
      //printf("ISGE\n");
      long fb = frame[INS_B(i)];
      long fc = frame[INS_C(i)];
      if (unlikely(1&(fc | fb))) {
	FAIL_SLOWPATH(fb, fc);
      }
      if (fb == fc) {
	pc+=2;
      } else {
	pc+=1;
      }
      DIRECT;
      break;
    }
    case 22: {
      L_INS_JISLT:
      long fb = frame[INS_B(i)];
      long fc = frame[INS_C(i)];
      if (unlikely(1&(fc | fb))) {
	FAIL_SLOWPATH(fb, fc);
      }
      if (fb < fc) {
	pc+=2;
      } else {
	pc+=1;
      }
      DIRECT;
      break;
    }
    case 10: {
      L_INS_ISLT:
      long fb = frame[INS_B(i)];
      long fc = frame[INS_C(i)];
      if (unlikely(1&(fc | fb))) {
	FAIL_SLOWPATH(fb, fc);
      }
      // TODO true/false
      if (fb < fc) {
	frame[INS_A(i)] = 1;
      } else {
	frame[INS_A(i)] = 0;
      }
      pc++;
      DIRECT;
      break;
    }
    case 19: {
      L_INS_ISEQ:
      long fb = frame[INS_B(i)];
      long fc = frame[INS_C(i)];
      if (unlikely(1&(fc | fb))) {
	FAIL_SLOWPATH(fb, fc);
      }
      // TODO true/false
      if (fb == fc) {
	frame[INS_A(i)] = 1;
      } else {
	frame[INS_A(i)] = 0;
      }
      pc++;
      DIRECT;
      break;
    }
    case 11: {
      L_INS_ISF:
      // TODO false
      if (0 == frame[INS_A(i)]) {
	pc+=1;
      } else {
	pc+=2;
      }
      DIRECT;
      break;
    }
    case 3: {
      L_INS_JMP:
      pc += INS_A(i);
      DIRECT;
      break;
    }
    case 4: {
      L_INS_RET1:
      // TODO constants
      pc = (unsigned int*)frame[-2];
      frame[-2] = frame[INS_A(i)];
      frame -= (INS_A(*(pc-1)) + 2);
      DIRECT;
      break;
    }
    case 5: {
      L_INS_SUBVN:
      long fb = frame[INS_B(i)];
      if (unlikely(1&fb)) {
	FAIL_SLOWPATH(fb, 0);
      }
      if (unlikely(__builtin_sub_overflow(fb, (INS_C(i) << 3), &frame[INS_A(i)]))) {
	FAIL_SLOWPATH(fb, 0);
      }
      pc++;
      DIRECT;
      break;
    }
    case 20: {
      L_INS_ADDVN:
      //printf("SUBVN\n");
      long fb = frame[INS_B(i)];
      if (unlikely(1&fb)) {
	FAIL_SLOWPATH(fb, 0);
      }
      if (unlikely(__builtin_add_overflow(fb, (INS_C(i) << 3), &frame[INS_A(i)]))) {
	FAIL_SLOWPATH(fb, 0);
      }
      pc++;
      DIRECT;
      break;
    }
    case 6: {
      L_INS_CALL:
      hotmap[((long)pc)%hotmap_sz] -= hotmap_rec;
      if (hotmap[((long)pc)%hotmap_sz] == 0) {
	HOTMAP_SLOWPATH(pc, frame[-1]);
	hotmap[((long)pc)%hotmap_sz] = 100;
      }
      auto v = frame[INS_A(i) + 1];
      if(unlikely((v & 0x7) != 5)) {
	FAIL_SLOWPATH(v, 0);
      }
      bcfunc* func = (bcfunc*)(v -5);
      frame[INS_A(i) + 1] = (long)func;
      auto old_pc = pc;
      pc = &func->code[0];
      frame[INS_A(i)] = (long)(old_pc + 1);
      if (unlikely((frame + 256 + 2 + INS_A(i)) > frame_top)) {
	auto pos = frame - stack;
	EXPAND_STACK_SLOWPATH();
	frame = stack + pos;
	frame_top = stack + stacksz;
      }
      frame += INS_A(i) + 2;
      // printf("Frame is %x\n", frame);
      DIRECT;
      break;
    }
    case 16: {
      L_INS_CALLT:
      hotmap[((long)pc)%hotmap_sz] -= hotmap_tail_rec;
      if (hotmap[((long)pc)%hotmap_sz] == 0) {
	HOTMAP_SLOWPATH(pc, frame[-1]);
	hotmap[((long)pc)%hotmap_sz] = 100;
      }
      // printf("CALL\n");
      // printf("Frame is %x\n", frame);
      auto v = frame[INS_A(i)];
      if(unlikely((v & 0x7) != 5)) {
	FAIL_SLOWPATH(v, 0);
      }
      bcfunc* func = (bcfunc*)(v -5);
      pc = &func->code[0];
      frame[-1] = (long)func;
      long start = INS_A(i) + 1;
      auto cnt = INS_B(i) - 1;
      for(auto i = 0; i < cnt; i++) {
	frame[i] = frame[start+i];
      }
      if (unlikely((frame + 256) > frame_top)) {
	auto pos = frame - stack;
	EXPAND_STACK_SLOWPATH();
	frame = stack + pos;
	frame_top = stack + stacksz;
      }
      // printf("Frame is %x\n", frame);
      DIRECT;
      break;
    }
      
    case 7: {
      L_INS_ADDVV:
      //printf("ADDVV");
      auto rb = frame[INS_B(i)];
      auto rc = frame[INS_C(i)];
      if (unlikely(1&(rb|rc))) {
	frame[INS_A(i)] = ADDVV_SLOWPATH(rb, rc);
      } else {
	if (unlikely(__builtin_add_overflow(rb, rc, &frame[INS_A(i)]))) {
	  frame[INS_A(i)] = ADDVV_SLOWPATH(rb, rc);
	}
      }
      pc++;
      DIRECT;
      break;
    }
    case 8: {
      L_INS_HALT:
      printf("Result:%li\n", frame[INS_A(i)] >> 3);
      return;
    }
    case 9: {
      L_INS_ALLOC:
      // TODO
      frame[INS_A(i)] = (long)malloc(INS_B(i));
      break;
    }
    case 12: {
      L_INS_SUBVV:
      long rb = frame[INS_B(i)];
      long rc = frame[INS_C(i)];
      if (unlikely(1&(rb|rc))) {
	frame[INS_A(i)] = ADDVV_SLOWPATH(rb, rc);
      } else {
	if (unlikely(__builtin_sub_overflow(rb, rc, &frame[INS_A(i)]))) {
	  FAIL_SLOWPATH(rb, rc);
	}
      }
      pc++;
      DIRECT;
      break;
    }
    case 13: {
      L_INS_GGET:
      bcfunc* func = (bcfunc*)frame[-1];
      symbol* gp = (symbol*)func->consts[INS_B(i)];
      if(unlikely(gp->val == UNDEFINED)) {
	UNDEFINED_SYMBOL_SLOWPATH(gp);
      }
      frame[INS_A(i)] = gp->val;
      pc++;
      DIRECT;
      break;
    }
    case 14: {
      L_INS_GSET:
      bcfunc* func = (bcfunc*)frame[-1];
      symbol* gp = (symbol*)func->consts[INS_A(i)];
      gp->val = frame[INS_B(i)];
      pc++;
      DIRECT;
      break;
    }
    case 15: {
      L_INS_KFUNC:
      bcfunc* f = funcs[INS_B(i)];
      // TODO func tag define
      frame[INS_A(i)] = ((long)f)+5;
      pc++;
      DIRECT;
      break;
    }
    case 17: {
      L_INS_KONST:
      bcfunc* func = (bcfunc*)frame[-1];
      frame[INS_A(i)] = func->consts[INS_B(i)];
      pc++;
      DIRECT;
      break;
    }
    case 18: {
      L_INS_MOV:
      frame[INS_B(i)] = frame[INS_A(i)];
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

  free(stack);
}