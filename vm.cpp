#include <string.h>
#include <assert.h>

#include "bytecode.h"
#include "record.h"
#include "replay.h"
#include "vm.h"
#include "asm_x64.h"

int joff = 0;

std::vector<bcfunc *> funcs;

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
__attribute__((noinline)) long ADDVV_SLOWPATH(long a, long b) {
  double c = (double)a + (double)b;
  c += 1.1;
  return c;
}
__attribute__((noinline)) long SUBVV_SLOWPATH(long a, long b) {
  double c = (double)a + (double)b;
  c += 1.1;
  return c;
}
__attribute__((noinline)) long FAIL_SLOWPATH(long a, long b) {
  printf("FAIL not an int\n");
  exit(-1);
  return a;
}
__attribute__((noinline)) void UNDEFINED_SYMBOL_SLOWPATH(symbol *s) {
  printf("FAIL undefined symbol: %s\n", s->name.c_str());
  exit(-1);
}
unsigned int stacksz = 1000;
static long *frame;
static long *frame_top;
long *stack = (long *)malloc(sizeof(long) * stacksz * 1000000);
__attribute__((noinline)) void EXPAND_STACK_SLOWPATH() {
  printf("Expand stack from %i to %i\n", stacksz, stacksz * 2);
  stacksz *= 2;
  stack = (long *)realloc(stack, stacksz * sizeof(long));
}

unsigned char hotmap[hotmap_sz];

#define PARAMS unsigned char ra, unsigned instr,unsigned* pc, long* frame, void** op_table_arg
#define ARGS ra, instr, pc, frame, op_table_arg
#define MUSTTAIL __attribute__((musttail))
//#define DEBUG(name) printf("%s %li %li %li %li\n", name, frame[0], frame[1], frame[2], frame[3]);
#define DEBUG(name)

typedef void (*op_func)(PARAMS);
static op_func op_table[25];
#define NEXT_INSTR { instr = *pc;		\
  unsigned char op = instr & 0xff;		\
  ra = (instr >> 8) & 0xff;			\
  instr >>= 16;					\
  op_func* op_table_arg_c = (op_func*)op_table_arg; \
  MUSTTAIL return op_table_arg_c[op](ARGS);		\
}


extern "C" {
void INS_FUNC(PARAMS) {
  DEBUG("FUNC");
  pc++;
  NEXT_INSTR;
}


void INS_KSHORT(PARAMS) {
  DEBUG("KSHORT");
  unsigned char rb = instr;

  frame[ra] = rb << 3;

  pc++;
  NEXT_INSTR;
}

void INS_JMP(PARAMS) {
  DEBUG("JMP");

  pc+= ra;
  NEXT_INSTR;
}

void INS_RET1(PARAMS) {
  DEBUG("RET1");

  pc = (unsigned int *)frame[-2];
  frame[-2] = frame[ra];
  frame -= (INS_A(*(pc - 1)) + 2);

  NEXT_INSTR;
}

void INS_HALT(PARAMS) {
  DEBUG("HALT");

  printf("Result:%li\n", frame[ra] >> 3);
  return;
}

void INS_ISGE(PARAMS) {
  DEBUG("ISGE");
  unsigned char rb = instr;

  long fa = frame[ra];
  long fb = frame[rb];
  if (unlikely(1 & (fa | fb))) {
    FAIL_SLOWPATH(fa, fb);
  }
  if (fa >= fb) {
    pc+=1;
  } else {
    pc+=2;
  }

  NEXT_INSTR;
}

void INS_SUBVN(PARAMS) {
  DEBUG("SUBVN");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  if (unlikely(1 & fb)) {
    FAIL_SLOWPATH(fb, 0);
  }
  if (unlikely(
	       __builtin_sub_overflow(fb, (rc << 3), &frame[ra]))) {
    FAIL_SLOWPATH(fb, 0);
  }
  pc++;

  NEXT_INSTR;
}

void INS_ADDVN(PARAMS) {
  DEBUG("ADDVN");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  if (unlikely(1 & fb)) {
    FAIL_SLOWPATH(fb, 0);
  }
  if (unlikely(
	       __builtin_add_overflow(fb, (rc << 3), &frame[ra]))) {
    FAIL_SLOWPATH(fb, 0);
  }
  pc++;

  NEXT_INSTR;
}

void INS_ADDVV(PARAMS) {
  DEBUG("ADDVV");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fb = frame[rb];
  auto fc = frame[rc];
  if (unlikely(1 & (fb | fc))) {
    frame[ra] = ADDVV_SLOWPATH(fb, fc);
  } else {
    if (unlikely(__builtin_add_overflow(fb, fc, &frame[ra]))) {
      frame[ra] = ADDVV_SLOWPATH(fb, fc);
    }
  }
  pc++;

  NEXT_INSTR;
}

void INS_SUBVV(PARAMS) {
  DEBUG("SUBVV");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fb = frame[rb];
  auto fc = frame[rc];
  if (unlikely(1 & (fb | fc))) {
    frame[ra] = SUBVV_SLOWPATH(fb, fc);
  } else {
    if (unlikely(__builtin_sub_overflow(fb, fc, &frame[ra]))) {
      frame[ra] = SUBVV_SLOWPATH(fb, fc);
    }
  }
  pc++;

  NEXT_INSTR;
}

void INS_GGET(PARAMS) {
  DEBUG("GGET");
  unsigned char rb = instr;

  bcfunc *func = (bcfunc *)(frame[-1] - 5);
  symbol *gp = (symbol *)func->consts[rb];
  if (unlikely(gp->val == UNDEFINED)) {
    UNDEFINED_SYMBOL_SLOWPATH(gp);
  }
  frame[ra] = gp->val;

  pc++;
  NEXT_INSTR;
}

void INS_GSET(PARAMS) {
  DEBUG("GSET");
  unsigned char rb = instr;

  bcfunc *func = (bcfunc *)(frame[-1] - 5);
  symbol *gp = (symbol *)func->consts[ra];
  gp->val = frame[rb];

  pc++;
  NEXT_INSTR;
}

void INS_KFUNC(PARAMS) {
  DEBUG("KFUNC");
  unsigned char rb = instr;

  frame[ra] = ((long)funcs[rb]) + 5;

  pc++;
  NEXT_INSTR;
}

void INS_CALL(PARAMS) {
  DEBUG("CALL");
  unsigned char rb = instr;

  if (unlikely((hotmap[(((long)pc) >> 2) & hotmap_mask] -=
		hotmap_tail_rec) == 0)) {
    //FAIL_SLOWPATH(0, 0);
    hotmap[(((long)pc) >> 2) & hotmap_mask] = hotmap_cnt;
    //goto L_INS_RECORD_START;
  }
  auto v = frame[ra + 1];
  if (unlikely((v & 0x7) != 5)) {
    FAIL_SLOWPATH(v, 0);
  }
  bcfunc *func = (bcfunc *)(v - 5);
  auto old_pc = pc;
  pc = &func->code[0];
  frame[ra] = long(old_pc + 1);
  if (unlikely((frame + 256 + 2 + ra) > frame_top)) {
    auto pos = frame - stack;
    EXPAND_STACK_SLOWPATH();
    frame = stack + pos;
    frame_top = stack + stacksz;
  }
  frame += ra + 2;
  
  NEXT_INSTR;
}
void INS_CALLT(PARAMS) {
  DEBUG("CALLT");
  unsigned char rb = instr;

  if (unlikely((hotmap[(((long)pc) >> 2) & hotmap_mask] -=
		hotmap_tail_rec) == 0)) {
    //FAIL_SLOWPATH(0, 0);
    hotmap[(((long)pc) >> 2) & hotmap_mask] = hotmap_cnt;
    //goto L_INS_RECORD_START;
  }
  auto v = frame[ra];
  if (unlikely((v & 0x7) != 5)) {
    FAIL_SLOWPATH(v, 0);
  }
  bcfunc *func = (bcfunc *)(v - 5);
  pc = &func->code[0];
  frame[-1] = v; // TODO move to copy loop
  long start = ra + 1;
  auto cnt = rb - 1;
  for (auto i = 0; i < cnt; i++) {
    frame[i] = frame[start + i];
  }
  // No need to stack size check for tailcalls since we reuse the frame.

  NEXT_INSTR;
}

void INS_KONST(PARAMS) {
  DEBUG("KONST");
  unsigned char rb = instr;

  bcfunc *func = (bcfunc *)(frame[-1] - 5);
  frame[ra] = func->consts[rb];

  pc++;
  NEXT_INSTR;
}

void INS_MOV(PARAMS) {
  DEBUG("MOV");
  unsigned char rb = instr;

  frame[rb] = frame[ra];

  pc++;
  NEXT_INSTR;
}

void INS_JISEQ(PARAMS) {
  DEBUG("JISEQ");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if (unlikely(1 & (fb | fc))) {
    FAIL_SLOWPATH(fb, fc);
  }
  if (fb == fc) {
    pc+=2;
  } else {
    pc+=1;
  }

  NEXT_INSTR;
}

void INS_JISLT(PARAMS) {
  DEBUG("JISLT");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if (unlikely(1 & (fb | fc))) {
    FAIL_SLOWPATH(fb, fc);
  }
  if (fb < fc) {
    pc+=2;
  } else {
    pc+=1;
  }

  NEXT_INSTR;
}

void INS_ISLT(PARAMS) {
  DEBUG("ISLT");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if (unlikely(1 & (fb | fc))) {
    FAIL_SLOWPATH(fb, fc);
  }
  if (fb < fc) {
    frame[ra] = 1;
  } else {
    frame[ra] = 0;
  }

  NEXT_INSTR;
}

void INS_ISEQ(PARAMS) {
  DEBUG("ISEQ");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if (unlikely(1 & (fb | fc))) {
    FAIL_SLOWPATH(fb, fc);
  }
  if (fb == fc) {
    frame[ra] = 1;
  } else {
    frame[ra] = 0;
  }

  NEXT_INSTR;
}

void INS_ISF(PARAMS) {
  DEBUG("ISF");

  long fa = frame[ra];
  if (ra == 0) {
    pc += 1;
  } else {
    pc += 2;
  }

  NEXT_INSTR;
}

void INS_UNKNOWN(PARAMS) {
  printf("UNIMPLEMENTED INSTRUCTION %s\n", ins_names[INS_OP(*pc)]);
  exit(-1);
}
}
void run() {

  op_table[1] = INS_KSHORT;

  
  unsigned int final_code[] = {CODE(CALL, 0, 1, 0), CODE(HALT, 0, 0, 0)};
  unsigned int *code = &funcs[0]->code[0];

  stack[0] = (unsigned long)&final_code[1]; // return pc
  stack[1] = ((unsigned long)funcs[0]) + 5; // func
  frame = &stack[2];
  frame_top = stack + stacksz;

  unsigned int *pc = &code[0];

  for (int i = 0; i < hotmap_sz; i++) {
    hotmap[i] = hotmap_cnt;
  }

  void *l_op_table[25];
  // clang-format off
  void* l_op_table_interpret[] = {
  };
  void* l_op_table_record[25];
  // clang-format on
  memcpy(l_op_table, l_op_table_interpret, sizeof(l_op_table));

  //////////NEW:
  for(int i = 0; i < 25; i++) {
    op_table[i] = INS_UNKNOWN;
  }
  op_table[0] = INS_FUNC;
  op_table[1] = INS_KSHORT;
  op_table[2] = INS_ISGE;
  op_table[3] = INS_JMP;
  op_table[4] = INS_RET1;
  op_table[5] = INS_SUBVN;
  op_table[6] = INS_CALL;
  op_table[7] = INS_ADDVV;
  op_table[8] = INS_HALT;
  op_table[10] = INS_ISLT;
  op_table[11] = INS_ISF;
  op_table[12] = INS_SUBVV;
  op_table[13] = INS_GGET;
  op_table[14] = INS_GSET;
  op_table[15] = INS_KFUNC;
  op_table[16] = INS_CALLT;
  op_table[17] = INS_KONST;
  op_table[18] = INS_MOV;
  op_table[19] = INS_ISEQ;
  op_table[20] = INS_ADDVN;
  op_table[21] = INS_JISEQ;
  op_table[22] = INS_JISLT;

    unsigned int instr = *pc;
    unsigned char op = instr & 0xff;
    unsigned char ra = (instr >> 8) & 0xff;
    instr >>= 16;
    auto op_table_arg = (void**)op_table; 
    op_table[op](ARGS);
    
    free(stack);

    
    // case 23: {
    // L_INS_JFUNC:
    //   // auto tnum = INS_B(i);
    //   // // printf("JFUNC/JLOOP run %i\n", tnum);
    //   // // printf("frame before %i %li %li \n", frame-stack, frame[0], frame[1]);
    //   // auto res = jit_run(tnum, &pc, &frame, frame_top);
    //   // frame_top = stack + stacksz;
    //   // //printf("frame after %i %li %li \n", frame-stack, frame[0], frame[1]);
    //   // if (unlikely(res)) {
    //   //   memcpy(l_op_table, l_op_table_record, sizeof(l_op_table));
    //   // }
    //   DIRECT;
    //   break;
    // }


    // {
    // L_INS_RECORD_START:
    //   hotmap[(((long)pc) >> 2) & hotmap_mask] = hotmap_cnt;
    //   if (joff) {
    //     //goto *l_op_table_interpret[INS_OP(i)];
    //   }
    //   // memcpy(l_op_table, l_op_table_record, sizeof(l_op_table));
    //   // // Don't record first inst.
    //   // goto *l_op_table_interpret[INS_OP(i)];
    // }

    // {
    // L_INS_RECORD:
    //   // if (record(pc, frame)) {
    //   //   memcpy(l_op_table, l_op_table_interpret, sizeof(l_op_table));
    //   // }
    //   // i = *pc; // recorder may have patched instruction.
    //   //goto *l_op_table_interpret[INS_OP(i)];
    //   1;
    // }
}
