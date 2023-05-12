#include <assert.h>
#include <string.h>

#include <gc/gc.h>

#include "asm_x64.h"
#include "bytecode.h"
#include "record.h"
#include "replay.h"
#include "types.h"
#include "vm.h"

int joff = 0;

std::vector<bcfunc *> funcs;

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
unsigned int stacksz = 1000;
static long *frame;
static long *frame_top;
long *stack = (long *)GC_malloc(sizeof(long) * stacksz);

unsigned char hotmap[hotmap_sz];

/*
This is a tail-calling interpreter that requires 'musttail' attribute, so
currently limited to only clang.

This ensures most things stay in registers, and any slowpaths are just jumps and
don't affect register allocation.

This could be improved by using a no-callee-saved register convention, like
llvm's cc10, but this isn't currently exposed to clang.

Currently this gives ~90% of the performance of a hand-coded assembly version,
while being more portable and easier to change.
 */

#define PARAMS                                                                 \
  unsigned char ra, unsigned instr, unsigned *pc, long *frame,                 \
      void **op_table_arg
#define ARGS ra, instr, pc, frame, op_table_arg
#define MUSTTAIL __attribute__((musttail))
//#define DEBUG(name)
#define DEBUG(name) printf("%s ra %i rd %i %li %li %li %li\n", name, ra, instr, frame[0], frame[1], frame[2], frame[3]);
typedef void (*op_func)(PARAMS);
static op_func l_op_table[INS_MAX];
static op_func l_op_table_record[INS_MAX];

#define NEXT_INSTR                                                             \
  {                                                                            \
    instr = *pc;                                                               \
    unsigned char op = instr & 0xff;                                           \
    ra = (instr >> 8) & 0xff;                                                  \
    instr >>= 16;                                                              \
    op_func *op_table_arg_c = (op_func *)op_table_arg;                         \
    MUSTTAIL return op_table_arg_c[op](ARGS);                                  \
  }

__attribute__((noinline)) void FAIL_SLOWPATH(PARAMS) {
  printf("FAIL\n");
  return;
}

void RECORD_START(PARAMS) {
  hotmap[(((long)pc) >> 2) & hotmap_mask] = hotmap_cnt;
  if (joff) {
    // Tail call with original op table.
    MUSTTAIL return l_op_table[INS_OP(*pc)](ARGS);
  }
  // Tail call with recording op table, but first instruction is not recorded.
  MUSTTAIL return l_op_table[INS_OP(*pc)](ra, instr, pc, frame,
                                          (void **)l_op_table_record);
}

void RECORD(PARAMS) {
  if (record(pc, frame)) {
    // Back to interpreting.
    op_table_arg = (void **)l_op_table;
  }
  // record may have updated state.
  instr = *pc;
  unsigned char op = instr & 0xff;
  ra = (instr >> 8) & 0xff;
  instr >>= 16;
  // Call interpret op table, but with record table.
  // Interprets *this* instruction, then advances to next
  MUSTTAIL return l_op_table[INS_OP(*pc)](ra, instr, pc, frame, op_table_arg);
}

void INS_FUNC(PARAMS) {
  DEBUG("FUNC");
  pc++;
  NEXT_INSTR;
}

void INS_KSHORT(PARAMS) {
  DEBUG("KSHORT");
  unsigned int rb = instr;

  frame[ra] = rb << 3;

  pc++;
  NEXT_INSTR;
}

void INS_JMP(PARAMS) {
  DEBUG("JMP");

  pc += ra;
  NEXT_INSTR;
}

void INS_RET1(PARAMS) {
  DEBUG("RET1");

  pc = (unsigned int *)frame[-1];
  frame[-1] = frame[ra];
  frame -= (INS_A(*(pc - 1)) + 1);

  NEXT_INSTR;
}

void INS_HALT(PARAMS) {
  DEBUG("HALT");

  printf("Result:");
  print_obj(frame[ra]);
  printf("\n");
  return;
}

void INS_ISGE(PARAMS) {
  DEBUG("ISGE");
  unsigned char rb = instr;

  long fa = frame[ra];
  long fb = frame[rb];
  if (unlikely(7 & (fa | fb))) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (fa >= fb) {
    pc += 1;
  } else {
    pc += 2;
  }

  NEXT_INSTR;
}

void INS_SUBVN(PARAMS) {
  DEBUG("SUBVN");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  if (unlikely(7 & fb)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (unlikely(__builtin_sub_overflow(fb, (rc << 3), &frame[ra]))) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  pc++;

  NEXT_INSTR;
}

void INS_ADDVN(PARAMS) {
  DEBUG("ADDVN");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  if (unlikely(7 & fb)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (unlikely(__builtin_add_overflow(fb, (rc << 3), &frame[ra]))) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
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
  if (likely((7 & (fb | fc)) == 0)) {
    if (unlikely(__builtin_add_overflow(fb, fc, &frame[ra]))) {
      MUSTTAIL return FAIL_SLOWPATH(ARGS);
    }
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {
    auto f1 = (flonum_s*)(fb-FLONUM_TAG);
    auto f2 = (flonum_s*)(fc-FLONUM_TAG);
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));
    r->x = f1->x + f2->x;
    frame[ra] = (long)r|FLONUM_TAG;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  pc++;

  NEXT_INSTR;
}

void INS_MULVV(PARAMS) {
  DEBUG("MULVV");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fb = frame[rb];
  auto fc = frame[rc];
  if (likely((7 & (fb | fc)) == 0)) {
    if (unlikely(__builtin_mul_overflow(fb, (fc >> 3), &frame[ra]))) {
      MUSTTAIL return FAIL_SLOWPATH(ARGS);
    }
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {
    auto f1 = (flonum_s*)(fb-FLONUM_TAG);
    auto f2 = (flonum_s*)(fc-FLONUM_TAG);
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));
    r->x = f1->x * f2->x;
    frame[ra] = (long)r|FLONUM_TAG;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
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
  if (likely((7 & (fb | fc)) == 0)) {
    if (unlikely(__builtin_sub_overflow(fb, fc, &frame[ra]))) {
      MUSTTAIL return FAIL_SLOWPATH(ARGS);
    }
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {
    auto f1 = (flonum_s*)(fb-FLONUM_TAG);
    auto f2 = (flonum_s*)(fc-FLONUM_TAG);
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));
    r->x = f1->x - f2->x;
    frame[ra] = (long)r|FLONUM_TAG;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  pc++;

  NEXT_INSTR;
}

void UNDEFINED_SYMBOL_SLOWPATH(PARAMS) {
  unsigned char rb = instr;

  symbol *gp = (symbol *)(const_table[rb] - SYMBOL_TAG);

  printf("FAIL undefined symbol: %s\n", gp->name->str);
  return;
}

void INS_GGET(PARAMS) {
  DEBUG("GGET");
  unsigned char rb = instr;

  symbol *gp = (symbol *)(const_table[rb] - SYMBOL_TAG);
  if (unlikely(gp->val == UNDEFINED_TAG)) {
    MUSTTAIL return UNDEFINED_SYMBOL_SLOWPATH(ARGS);
  }
  frame[ra] = gp->val;

  pc++;
  NEXT_INSTR;
}

void INS_GSET(PARAMS) {
  DEBUG("GSET");
  unsigned char rb = instr;

  symbol *gp = (symbol *)(const_table[ra] - SYMBOL_TAG);
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

__attribute__((noinline)) void EXPAND_STACK_SLOWPATH(PARAMS) {
  printf("Expand stack from %i to %i\n", stacksz, stacksz * 2);
  auto pos = frame - stack;
  stacksz *= 2;
  stack = (long *)realloc(stack, stacksz * sizeof(long));
  frame = stack + pos;
  frame_top = stack + stacksz;

  NEXT_INSTR;
}

void INS_CALL(PARAMS) {
  DEBUG("CALL");
  unsigned char rb = instr;

  if (unlikely((hotmap[(((long)pc) >> 2) & hotmap_mask] -= hotmap_tail_rec) ==
               0)) {
    MUSTTAIL return RECORD_START(ARGS);
  }
  auto v = frame[ra];
  if (unlikely((v & 0x7) != 5)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  bcfunc *func = (bcfunc *)(v - 5);
  auto old_pc = pc;
  pc = &func->code[0];
  frame[ra] = long(old_pc + 1);
  frame += ra + 1;
  if (unlikely((frame + 256) > frame_top)) {
    MUSTTAIL return EXPAND_STACK_SLOWPATH(ARGS);
  }

  NEXT_INSTR;
}
void INS_CALLT(PARAMS) {
  DEBUG("CALLT");
  unsigned char rb = instr;

  if (unlikely((hotmap[(((long)pc) >> 2) & hotmap_mask] -= hotmap_tail_rec) ==
               0)) {
    MUSTTAIL return RECORD_START(ARGS);
  }
  auto v = frame[ra];
  if (unlikely((v & 0x7) != 5)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  bcfunc *func = (bcfunc *)(v - 5);
  pc = &func->code[0];

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
  frame[ra] = const_table[rb];

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
  if (likely((7 & (fb | fc)) == 0)) {
    if (fb == fc) {
      pc += 2;
    } else {
      pc += 1;
    }
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {
    auto f1 = (flonum_s*)(fb-FLONUM_TAG);
    auto f2 = (flonum_s*)(fc-FLONUM_TAG);
    if (f1->x == f2->x) {
      pc += 2;
    } else {
      pc += 1;
    }
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }

  NEXT_INSTR;
}

void INS_JISLT(PARAMS) {
  DEBUG("JISLT");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if (likely((7 & (fb | fc)) == 0)) {
    if (fb < fc) {
      pc += 2;
    } else {
      pc += 1;
    }
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {
    auto f1 = (flonum_s*)(fb-FLONUM_TAG);
    auto f2 = (flonum_s*)(fc-FLONUM_TAG);
    if (f1->x < f2->x) {
      pc += 2;
    } else {
      pc += 1;
    }
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }

  NEXT_INSTR;
}

void INS_ISLT(PARAMS) {
  DEBUG("ISLT");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if (unlikely(7 & (fb | fc))) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (fb < fc) {
    frame[ra] = TRUE_REP;
  } else {
    frame[ra] = FALSE_REP;
  }
  pc++;

  NEXT_INSTR;
}

void INS_ISEQ(PARAMS) {
  DEBUG("ISEQ");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if (unlikely(7 & (fb | fc))) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (fb == fc) {
    frame[ra] = TRUE_REP;
  } else {
    frame[ra] = FALSE_REP;
  }

  NEXT_INSTR;
}

void INS_ISF(PARAMS) {
  DEBUG("ISF");

  long fa = frame[ra];
  if (fa == FALSE_REP) {
    pc += 1;
  } else {
    pc += 2;
  }

  NEXT_INSTR;
}

void INS_JFUNC(PARAMS) {
  DEBUG("JFUNC");
  auto tnum = instr;
  // printf("JFUNC/JLOOP run %i\n", tnum);
  // printf("frame before %i %li %li \n", frame-stack, frame[0], frame[1]);
  // auto res = record_run(tnum, &pc, &frame, frame_top);
  auto res = jit_run(tnum, &pc, &frame, frame_top);
  frame_top = stack + stacksz;
  // printf("frame after %i %li %li \n", frame-stack, frame[0], frame[1]);
  if (unlikely(res)) {
    // Turn on recording again
    op_table_arg = (void **)l_op_table_record;
  }
  NEXT_INSTR;
}

void INS_GUARD(PARAMS) {
  DEBUG("GUARD");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];

  // typecheck fb vs. rc.
  if ((rc < LITERAL_TAG) && ((fb&TAG_MASK) == rc)) {
    frame[ra] = TRUE_REP;
  } else if (((TAG_MASK&rc) == LITERAL_TAG) && (rc == (fb&IMMEDIATE_MASK))) {
    frame[ra] = TRUE_REP;
  } else if (((fb&TAG_MASK) == PTR_TAG) && (*(long*)(fb-PTR_TAG) == rc)) {
    frame[ra] = TRUE_REP;
  } else {
    frame[ra] = FALSE_REP;
  }
  pc++;

  NEXT_INSTR;
}

void INS_BOX(PARAMS) {
  DEBUG("BOX");
  unsigned char rb = instr;

  long fb = frame[rb];

  auto box = (cons_s*)GC_malloc(sizeof(cons_s));
  box->a = fb;
  box->b = NIL_TAG;
  frame[ra] = (long)box|PTR_TAG;
  pc++;

  NEXT_INSTR;
}

void INS_UNBOX(PARAMS) {
  DEBUG("UNBOX");
  unsigned char rb = instr;

  long fb = frame[rb];
  auto box = (cons_s*)(fb - PTR_TAG);
  frame[ra] = box->a;
  pc++;

  NEXT_INSTR;
}

void INS_SET_BOX(PARAMS) {
  DEBUG("SET-BOX!");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];

  auto box = (cons_s*)(fb - PTR_TAG);
  box->a = fc;
  frame[ra] = UNDEFINED_TAG;
  pc++;

  NEXT_INSTR;
}

void INS_UNKNOWN(PARAMS) {
  printf("UNIMPLEMENTED INSTRUCTION %s\n", ins_names[INS_OP(*pc)]);
  exit(-1);
}

void run() {
  // Bytecode stub to get us to HALT.
  unsigned int final_code[] = {CODE(CALL, 0, 1, 0), CODE(HALT, 0, 0, 0)};
  unsigned int *code = &funcs[0]->code[0];

  // Initial stack setup has a return to bytecode stub above.
  stack[0] = (unsigned long)&final_code[1]; // return pc
  frame = &stack[1];
  frame_top = stack + stacksz;

  unsigned int *pc = &code[0];

  for (int i = 0; i < hotmap_sz; i++) {
    hotmap[i] = hotmap_cnt;
  }

  // Setup instruction table.
  for (int i = 0; i < INS_MAX; i++) {
    l_op_table[i] = INS_UNKNOWN;
  }
  l_op_table[0] = INS_FUNC;
  l_op_table[1] = INS_KSHORT;
  l_op_table[2] = INS_ISGE;
  l_op_table[3] = INS_JMP;
  l_op_table[4] = INS_RET1;
  l_op_table[5] = INS_SUBVN;
  l_op_table[6] = INS_CALL;
  l_op_table[7] = INS_ADDVV;
  l_op_table[8] = INS_HALT;
  l_op_table[10] = INS_ISLT;
  l_op_table[11] = INS_ISF;
  l_op_table[12] = INS_SUBVV;
  l_op_table[13] = INS_GGET;
  l_op_table[14] = INS_GSET;
  l_op_table[15] = INS_KFUNC;
  l_op_table[16] = INS_CALLT;
  l_op_table[17] = INS_KONST;
  l_op_table[18] = INS_MOV;
  l_op_table[19] = INS_ISEQ;
  l_op_table[20] = INS_ADDVN;
  l_op_table[21] = INS_JISEQ;
  l_op_table[22] = INS_JISLT;
  l_op_table[23] = INS_JFUNC;
  l_op_table[24] = INS_JFUNC; // JLOOP
  l_op_table[25] = INS_GUARD; 
  l_op_table[26] = INS_MULVV; 
  l_op_table[BOX] = INS_BOX; 
  l_op_table[UNBOX] = INS_UNBOX; 
  l_op_table[SET_BOX] = INS_SET_BOX; 
  for (int i = 0; i < INS_MAX; i++) {
    l_op_table_record[i] = RECORD;
  }

  // Initial tailcalling-interpreter variable setup.
  unsigned int instr = *pc;
  unsigned char op = instr & 0xff;
  unsigned char ra = (instr >> 8) & 0xff;
  instr >>= 16;
  auto op_table_arg = (void **)l_op_table;
  l_op_table[op](ARGS);

  // And after the call returns, we're done.  only HALT returns.
}
