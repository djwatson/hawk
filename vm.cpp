#include <assert.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>

#include "asm_x64.h"
#include "bytecode.h"
#include "record.h"
#include "replay.h"
#include "types.h"
#include "vm.h"
#include "symbol_table.h"
#include "gc.h"


int joff = 0;

std::vector<bcfunc *> funcs;

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
long *frame_top;
unsigned int stacksz = 1000;
long *stack = (long *)malloc(sizeof(long) * stacksz );

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
    void **op_table_arg, long argcnt
#define ARGS ra, instr, pc, frame, op_table_arg, argcnt
#define MUSTTAIL __attribute((musttail))
#define ABI __attribute__((ms_abi))
#define DEBUG(name)
//#define DEBUG(name) printf("%s ra %i rd %i rb %i rc %i ", name, ra, instr, instr&0xff, (instr>>8)); printf("\n");
typedef ABI void (*op_func)(PARAMS);
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



ABI __attribute__((noinline)) void FAIL_SLOWPATH(PARAMS) {
  int i = 0;
  printf("FAIL PC: %p %s\n", pc, ins_names[INS_OP(*pc)]);
  while(&frame[-1] > stack) {
    for(unsigned long j = 0; j < funcs.size(); j++) {
      if (pc >= &funcs[j]->code[0] &&
	  pc < &funcs[j]->code[funcs[j]->code.size()-1]) {
	printf("FUNC %li: %s PC %li\n",j, funcs[j]->name.c_str(), pc - &funcs[j]->code[0]);
	break;
      }
    }
    pc = (unsigned int *)frame[-1];
    frame[-1] = frame[ra];
    frame -= (INS_A(*(pc - 1)) + 1);
    printf("%i PC: %p\n", i++, pc);
  }
  return;
}

ABI __attribute__((noinline)) void FAIL_SLOWPATH_ARGCNT(PARAMS) {
  printf("FAIL ARGCNT INVALID\n");
  
  MUSTTAIL return FAIL_SLOWPATH(ARGS);
}

ABI void RECORD_START(PARAMS) {
  hotmap[(((long)pc) >> 2) & hotmap_mask] = hotmap_cnt;
  if (joff) {
    // Tail call with original op table.
    MUSTTAIL return l_op_table[INS_OP(*pc)](ARGS);
  }
  // Tail call with recording op table, but first instruction is not recorded.
  MUSTTAIL return l_op_table[INS_OP(*pc)](ra, instr, pc, frame,
                                          (void **)l_op_table_record, argcnt);
}

ABI void RECORD(PARAMS) {
  if (1 /*record(pc, frame)*/) {
    // Back to interpreting.
    op_table_arg = (void **)l_op_table;
  }
  // record may have updated state.
  instr = *pc;
  ra = (instr >> 8) & 0xff;
  instr >>= 16;
  // Call interpret op table, but with record table.
  // Interprets *this* instruction, then advances to next
  MUSTTAIL return l_op_table[INS_OP(*pc)](ra, instr, pc, frame, op_table_arg, argcnt);
}

long build_list(long start, long len, long*frame) {
  long lst = NIL_TAG;
  // printf("Build list from %i len %i\n", start, len);
  for(long pos = start+len-1; pos >= start; pos--) {
    GC_push_root(&lst); // TODO just save in POS instead?
    auto c = (cons_s *)GC_malloc(sizeof(cons_s));
    GC_pop_root(&lst); // TODO just save in POS instead?
    c->type = CONS_TAG;
    c->a = frame[pos];
    c->b = lst;
    lst = (long)c + CONS_TAG;
  }
  // printf("build_list Result:");
  // print_obj(lst);
  // printf("\n");
  return lst;
}

ABI __attribute__((noinline)) void UNDEFINED_SYMBOL_SLOWPATH(PARAMS) {
  auto rd = instr;

  symbol *gp = (symbol *)(const_table[rd] - SYMBOL_TAG);

  printf("FAIL undefined symbol: %s\n", gp->name->str);
  return;
}


ABI __attribute__((noinline)) void EXPAND_STACK_SLOWPATH(PARAMS) {
  printf("Expand stack from %i to %i\n", stacksz, stacksz * 2);
  auto pos = frame - stack;
  auto oldsz = stacksz;
  stacksz *= 2;
  stack = (long *)realloc(stack, stacksz * sizeof(long));
  memset(&stack[oldsz], 0, sizeof(long)*(stacksz - oldsz));
  frame = stack + pos;
  frame_top = stack + stacksz;

  NEXT_INSTR;
}

ABI void INS_JISEQ(PARAMS) {
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

ABI void INS_JEQ(PARAMS) {
  DEBUG("JEQ");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if (fb == fc) {
    pc += 2;
  } else {
    pc += 1;
  }

  NEXT_INSTR;
}

ABI __attribute__((noinline)) void INS_JISLT_SLOWPATH(PARAMS) {
  DEBUG("JISLT_SLOWPATH");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fb = frame[rb];
  auto fc = frame[rc];
  double x_b;
  double x_c;
  // Assume convert to flonum.
  if ((fb&TAG_MASK) == FLONUM_TAG) {
    x_b = ((flonum_s*)(fb-FLONUM_TAG))->x;
  } else if ((fb&TAG_MASK) == FIXNUM_TAG) {
    x_b = fb >> 3;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if ((fc&TAG_MASK) == FLONUM_TAG) {
    x_c = ((flonum_s*)(fc-FLONUM_TAG))->x;
  } else if ((fc&TAG_MASK) == FIXNUM_TAG) {
    x_c = fc >> 3;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }

  if (x_b < x_c) {
    pc += 2;
  } else {
    pc += 1;
  }
  
  NEXT_INSTR;
}

ABI void INS_JISLT(PARAMS) {
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
    MUSTTAIL return INS_JISLT_SLOWPATH(ARGS);
  }

  NEXT_INSTR;
}

ABI __attribute__((noinline)) void INS_ISLT_SLOWPATH(PARAMS) {
  DEBUG("ISLT_SLOWPATH");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fb = frame[rb];
  auto fc = frame[rc];
  double x_b;
  double x_c;
  // Assume convert to flonum.
  if ((fb&TAG_MASK) == FLONUM_TAG) {
    x_b = ((flonum_s*)(fb-FLONUM_TAG))->x;
  } else if ((fb&TAG_MASK) == FIXNUM_TAG) {
    x_b = fb >> 3;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if ((fc&TAG_MASK) == FLONUM_TAG) {
    x_c = ((flonum_s*)(fc-FLONUM_TAG))->x;
  } else if ((fc&TAG_MASK) == FIXNUM_TAG) {
    x_c = fc >> 3;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }

  if (x_b < x_c) {
    frame[ra] = TRUE_REP;
  } else {
    frame[ra] = FALSE_REP;
  }
  pc++;
  
  NEXT_INSTR;
}

ABI void INS_ISLT(PARAMS) {
  DEBUG("ISLT");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if (unlikely(7 & (fb | fc))) {
    MUSTTAIL return INS_ISLT_SLOWPATH(ARGS);
  }
  if (fb < fc) {
    frame[ra] = TRUE_REP;
  } else {
    frame[ra] = FALSE_REP;
  }
  pc++;

  NEXT_INSTR;
}

ABI void INS_ISEQ(PARAMS) {
  DEBUG("ISEQ");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if (likely((7 & (fb | fc)) == 0)) {
    if (fb == fc) {
      frame[ra] = TRUE_REP;
    } else {
      frame[ra] = FALSE_REP;
    }
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {
    auto f1 = (flonum_s*)(fb-FLONUM_TAG);
    auto f2 = (flonum_s*)(fc-FLONUM_TAG);
    if (f1->x == f2->x) {
      frame[ra] = TRUE_REP;
    } else {
      frame[ra] = FALSE_REP;
    }
  } else if (((TAG_MASK&fb) == FLONUM_TAG || (TAG_MASK&fb) == FIXNUM_TAG) &&
	     ((TAG_MASK&fc) == FLONUM_TAG || (TAG_MASK&fc) == FIXNUM_TAG)) {
    frame[ra] = FALSE_REP;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  pc++;

  NEXT_INSTR;
}

ABI void INS_ISF(PARAMS) {
  DEBUG("ISF");

  long fa = frame[ra];
  if (fa == FALSE_REP) {
    pc += 1;
  } else {
    pc += 2;
  }

  NEXT_INSTR;
}

#define INS_JLOOP INS_JFUNC
ABI void INS_JFUNC(PARAMS) {
  DEBUG("JFUNC");
  //auto tnum = instr;
  // printf("JFUNC/JLOOP run %i\n", tnum);
  // printf("frame before %i %li %li \n", frame-stack, frame[0], frame[1]);
  // auto res = record_run(tnum, &pc, &frame, frame_top);
  //auto res = jit_run(tnum, &pc, &frame, frame_top);
  int res = 0;
  frame_top = stack + stacksz;
  // printf("frame after %i %li %li \n", frame-stack, frame[0], frame[1]);
  if (unlikely(res)) {
    // Turn on recording again
    op_table_arg = (void **)l_op_table_record;
  }
  NEXT_INSTR;
}

ABI void INS_GUARD(PARAMS) {
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

#include "stdlib.cpp"


ABI void INS_APPLY(PARAMS) {
  DEBUG("APPLY");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fun = frame[rb];
  if (unlikely((fun&TAG_MASK) != CLOSURE_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  // TODO check type NIL
  auto args = frame[rc];

  long a = 0;
  for(;(args&TAG_MASK) == CONS_TAG;a++) {
    auto cons = (cons_s*)(args-CONS_TAG);
    frame[a+1] = cons->a;
    args = cons->b;
  }
  frame[0] = fun;
  auto clo = (closure_s*)(fun-CLOSURE_TAG);
  auto func = (bcfunc*)clo->v[0];
  pc = &func->code[0];
  argcnt = a+1;

  NEXT_INSTR;
}

ABI __attribute__((noinline)) void INS_DIV_SLOWPATH(PARAMS) {
  DEBUG("DIV_SLOWPATH");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  // TODO check for divide by zero
  auto fb = frame[rb];
  auto fc = frame[rc];
  double x_b;
  double x_c;
  // Assume convert to flonum.
  if ((fb&TAG_MASK) == FLONUM_TAG) {
    x_b = ((flonum_s*)(fb-FLONUM_TAG))->x;
  } else if ((fb&TAG_MASK) == FIXNUM_TAG) {
    x_b = fb >> 3;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if ((fc&TAG_MASK) == FLONUM_TAG) {
    x_c = ((flonum_s*)(fc-FLONUM_TAG))->x;
  } else if ((fc&TAG_MASK) == FIXNUM_TAG) {
    x_c = fc >> 3;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }

  auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));
  r->x = x_b / x_c;
  r->type = FLONUM_TAG;
  frame[ra] = (long)r|FLONUM_TAG;
  pc++;

  NEXT_INSTR;
}

ABI void INS_DIV(PARAMS) {
  DEBUG("DIV");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  // TODO check for divide by zero
  auto fb = frame[rb];
  auto fc = frame[rc];
  if (likely((7 & (fb | fc)) == 0)) {
    frame[ra] = (fb/fc) << 3;
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {
    auto f1 = ((flonum_s*)(fb-FLONUM_TAG))->x;
    auto f2 = ((flonum_s*)(fc-FLONUM_TAG))->x;
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));
    r->x = f1 / f2;
    r->type = FLONUM_TAG;
    frame[ra] = (long)r|FLONUM_TAG;
  } else {
    MUSTTAIL return INS_DIV_SLOWPATH(ARGS);
  }
  pc++;

  NEXT_INSTR;
}

ABI void INS_REM(PARAMS) {
  DEBUG("REM");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fb = frame[rb];
  auto fc = frame[rc];
  if (likely((7 & (fb | fc)) == 0)) {
    frame[ra] = ((fb >>3 ) % (fc >> 3)) << 3;
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {
    auto f1 = ((flonum_s*)(fb-FLONUM_TAG))->x;
    auto f2 = ((flonum_s*)(fc-FLONUM_TAG))->x;
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));
    r->x = remainder(f1, f2);
    r->type = FLONUM_TAG;
    frame[ra] = (long)r|FLONUM_TAG;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  pc++;

  NEXT_INSTR;
}

void run(bcfunc* func, long argcnt, long * args) {
  // Bytecode stub to get us to HALT.
  unsigned int final_code[] = {CODE(CALL, 0, 1, 0), CODE(HALT, 0, 0, 0)};
  unsigned int *code = &func->code[0];

  long *frame;
  // Initial stack setup has a return to bytecode stub above.

  stack[0] = (unsigned long)&final_code[1]; // return pc
  frame = &stack[1];
  frame_top = stack + stacksz;

  for(long i = 0; i < argcnt; i++) {
    frame[i] = args[i];
  }

  unsigned int *pc = &code[0];

  for (int i = 0; i < hotmap_sz; i++) {
    hotmap[i] = hotmap_cnt;
  }

  // Setup instruction table.
  #include "opcodes-table.h"
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
