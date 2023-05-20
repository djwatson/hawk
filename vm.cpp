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

void*GC_malloc(size_t);

int joff = 0;

std::vector<bcfunc *> funcs;

void* GC_malloc(size_t sz) {
  auto res = calloc(sz, 1);
  return res;
}

void* GC_realloc(void* ptr, size_t sz) {
  // TODO zero-mem
  return realloc(ptr, sz);
}

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
long *frame_top;
unsigned int stacksz = 1000 * 100000;
long *stack = (long *)GC_malloc(sizeof(long) * stacksz );

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
#define MUSTTAIL __attribute__((musttail))
#define DEBUG(name)
//#define DEBUG(name) printf("%s ra %i rd %i rb %i rc %i ", name, ra, instr, instr&0xff, (instr>>8)); printf("\n");
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
  int i = 0;
  printf("FAIL PC: %p\n", pc);
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

__attribute__((noinline)) void FAIL_SLOWPATH_ARGCNT(PARAMS) {
  printf("FAIL ARGCNT INVALID\n");
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
                                          (void **)l_op_table_record, argcnt);
}

void RECORD(PARAMS) {
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

long cons(long a, long b) {
  auto c = (cons_s *)GC_malloc(sizeof(cons_s));
  c->a = a;
  c->b = b;
  return (long)c | CONS_TAG;
}

long build_list(long start, long len, long*frame) {
  long lst = NIL_TAG;
  // printf("Build list from %i len %i\n", start, len);
  for(long pos = start+len-1; pos >= start; pos--) {
    lst = cons(frame[pos], lst);
  }
  // printf("build_list Result:");
  // print_obj(lst);
  // printf("\n");
  return lst;
}

void INS_FUNC(PARAMS) {
  DEBUG("FUNC");
  unsigned int rb = instr;

  // vararg
  //printf("FUNC vararg %i args %i argcnt %i\n", rb, ra, argcnt);
  if (rb) {
    if (argcnt < ra) {
      MUSTTAIL return FAIL_SLOWPATH_ARGCNT(ARGS);
    }
    frame[ra] = build_list(ra, argcnt -ra, frame);
  } else {
    if (argcnt != ra) {
      MUSTTAIL return FAIL_SLOWPATH_ARGCNT(ARGS);
    }
  }
  pc++;
  NEXT_INSTR;
}

void INS_KSHORT(PARAMS) {
  DEBUG("KSHORT");
  auto rd = (int16_t)instr;

  frame[ra] = rd << 3;

  pc++;
  NEXT_INSTR;
}

void INS_JMP(PARAMS) {
  DEBUG("JMP");
  auto rd = (uint16_t)instr;

  pc += rd;
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

  // printf("Result:");
  // print_obj(frame[ra]);
  // printf("\n");
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
  char rc = (instr >> 8) & 0xff;

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
  char rc = (instr >> 8) & 0xff;

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
  auto rd = instr;

  symbol *gp = (symbol *)(const_table[rd] - SYMBOL_TAG);

  printf("FAIL undefined symbol: %s\n", gp->name->str);
  return;
}

void INS_GGET(PARAMS) {
  DEBUG("GGET");
  auto rd = instr;

  symbol *gp = (symbol *)(const_table[rd] - SYMBOL_TAG);
  if (unlikely(gp->val == UNDEFINED_TAG)) {
    MUSTTAIL return UNDEFINED_SYMBOL_SLOWPATH(ARGS);
  }
  frame[ra] = gp->val;

  pc++;
  NEXT_INSTR;
}

void INS_GSET(PARAMS) {
  DEBUG("GSET");
  auto rd = instr;

  symbol *gp = (symbol *)(const_table[rd] - SYMBOL_TAG);
  gp->val = frame[ra];

  pc++;
  NEXT_INSTR;
}

void INS_KFUNC(PARAMS) {
  DEBUG("KFUNC");
  auto rb = instr;

  frame[ra] = (long)funcs[rb];

  pc++;
  NEXT_INSTR;
}

__attribute__((noinline)) void EXPAND_STACK_SLOWPATH(PARAMS) {
  printf("Expand stack from %i to %i\n", stacksz, stacksz * 2);
  auto pos = frame - stack;
  auto oldsz = stacksz;
  stacksz *= 2;
  stack = (long *)GC_realloc(stack, stacksz * sizeof(long));
  memset(&stack[oldsz], 0, sizeof(long)*(stacksz - oldsz));
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
  bcfunc *func = (bcfunc *)v;
  auto old_pc = pc;
  pc = &func->code[0];
  frame[ra] = long(old_pc + 1);
  frame += ra + 1;
  argcnt = rb - 1;
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
  bcfunc *func = (bcfunc *)v;
  pc = &func->code[0];

  long start = ra + 1;
  argcnt = rb - 1;
  for (auto i = 0; i < argcnt; i++) {
    frame[i] = frame[start + i];
  }
  // No need to stack size check for tailcalls since we reuse the frame.

  NEXT_INSTR;
}

void INS_KONST(PARAMS) {
  DEBUG("KONST");
  auto rd = instr;

  frame[ra] = const_table[rd];

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

void INS_JEQ(PARAMS) {
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
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  pc++;

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
  //frame[ra] = UNDEFINED_TAG;
  pc++;

  NEXT_INSTR;
}

void INS_CLOSURE(PARAMS) {
  DEBUG("CLOSURE");
  unsigned char rb = instr;

  auto closure = (closure_s*)GC_malloc(sizeof(long)*(rb + 1));
  closure->len = rb;
  for(int i = 0; i < rb; i++) {
    closure->v[i] = frame[ra + i];
  }
  frame[ra] = (long)closure|CLOSURE_TAG;

  pc++;
  NEXT_INSTR;
}

void INS_CLOSURE_PTR(PARAMS) {
  DEBUG("CLOSURE-PTR");
  unsigned char rb = instr & 0xff;

  auto fb = frame[rb];
  if (unlikely((fb & 0x7) != CLOSURE_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto closure = (closure_s*)(fb-CLOSURE_TAG);
  frame[ra] = closure->v[0];

  pc++;
  NEXT_INSTR;
}

void INS_CLOSURE_GET(PARAMS) {
  DEBUG("CLOSURE-GET");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fb = frame[rb];
  if (unlikely((fb & 0x7) != CLOSURE_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto closure = (closure_s*)(fb-CLOSURE_TAG);
  frame[ra] = closure->v[1 + rc];

  pc++;
  NEXT_INSTR;
}

void INS_CLOSURE_SET(PARAMS) {
  DEBUG("CLOSURE-SET");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fa = frame[ra];
  // No need to typecheck, that would be bad bytecode.
  auto closure = (closure_s*)(fa-CLOSURE_TAG);
  closure->v[1 + rc] = frame[rb];

  pc++;
  NEXT_INSTR;
}

void INS_EQ(PARAMS) {
  DEBUG("EQ");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if (fb == fc) {
    frame[ra] = TRUE_REP;
  } else {
    frame[ra] = FALSE_REP;
  }
  pc++;

  NEXT_INSTR;
}

void INS_CONS(PARAMS) {
  DEBUG("CONS");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  frame[ra] = cons(fb, fc);
  pc++;

  NEXT_INSTR;
}

void INS_CAR(PARAMS) {
  DEBUG("CAR");
  unsigned char rb = instr & 0xff;

  auto fb = frame[rb];
  if(unlikely((fb&TAG_MASK) != CONS_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto c = (cons_s*)(fb-CONS_TAG);
  frame[ra] = c->a;
  pc++;

  NEXT_INSTR;
}

void INS_CDR(PARAMS) {
  DEBUG("CDR");
  unsigned char rb = instr & 0xff;

  auto fb = frame[rb];
  if(unlikely((fb&TAG_MASK) != CONS_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto c = (cons_s*)(fb-CONS_TAG);
  frame[ra] = c->b;
  pc++;

  NEXT_INSTR;
}

void INS_MAKE_VECTOR(PARAMS) {
  DEBUG("MAKE_VECTOR");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if(unlikely((fb&TAG_MASK) != FIXNUM_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto len = fb>>3;
  auto vec = (vector_s*)GC_malloc( sizeof(long) * (len + 2));
  vec->type = VECTOR_TAG;
  vec->len = len;
  for(long i = 0; i < len; i++) {
    vec->v[i] = fc;
  }
  
  frame[ra] = (long)vec | PTR_TAG;
  pc++;

  NEXT_INSTR;
}

void INS_MAKE_STRING(PARAMS) {
  DEBUG("MAKE_STRING");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  long fb = frame[rb];
  long fc = frame[rc];
  if(unlikely((fb&TAG_MASK) != FIXNUM_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if(unlikely((fc&IMMEDIATE_MASK) != CHAR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto len = fb>>3;
  auto str = (string_s*)GC_malloc( (sizeof(long) * 2) + len + 1);
  str->type = STRING_TAG;
  str->len = len;
  for(long i = 0; i < len; i++) {
    str->str[i] = (fc >> 8)&0xff;
  }
  str->str[len] = '\0';
  
  frame[ra] = (long)str | PTR_TAG;
  pc++;

  NEXT_INSTR;
}

void INS_VECTOR_REF(PARAMS) {
  DEBUG("VECTOR_REF");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fb = frame[rb];
  auto fc = frame[rc];
  if (unlikely((fb & 0x7) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (unlikely((fc&TAG_MASK) != FIXNUM_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto vec = (vector_s*)(fb-PTR_TAG);
  if (unlikely(vec->type != VECTOR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = vec->v[fc>>3];

  pc++;
  NEXT_INSTR;
}

void INS_STRING_REF(PARAMS) {
  DEBUG("STRING_REF");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fb = frame[rb];
  auto fc = frame[rc];
  if (unlikely((fb & 0x7) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (unlikely((fc&TAG_MASK) != FIXNUM_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto str = (string_s*)(fb-PTR_TAG);
  if (unlikely(str->type != STRING_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = (str->str[fc>>3] << 8)|CHAR_TAG;

  pc++;
  NEXT_INSTR;
}

void INS_VECTOR_LENGTH(PARAMS) {
  DEBUG("VECTOR_LENGTH");
  unsigned char rb = instr & 0xff;

  auto fb = frame[rb];
  if (unlikely((fb & 0x7) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto vec = (vector_s*)(fb-PTR_TAG);
  if (unlikely(vec->type != VECTOR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = vec->len << 3;

  pc++;
  NEXT_INSTR;
}

void INS_STRING_LENGTH(PARAMS) {
  DEBUG("STRING_LENGTH");
  unsigned char rb = instr & 0xff;

  auto fb = frame[rb];
  if (unlikely((fb & 0x7) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto str = (string_s*)(fb-PTR_TAG);
  if (unlikely(str->type != STRING_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = str->len << 3;

  pc++;
  NEXT_INSTR;
}

void INS_VECTOR_SET(PARAMS) {
  DEBUG("VECTOR-SET!");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fa = frame[ra];
  auto fb = frame[rb];
  auto fc = frame[rc];
  if (unlikely((fa & 0x7) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (unlikely((fb&TAG_MASK) != FIXNUM_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto vec = (vector_s*)(fa-PTR_TAG);
  if (unlikely(vec->type != VECTOR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  vec->v[fb >> 3] = fc;

  pc++;
  NEXT_INSTR;
}

void INS_STRING_SET(PARAMS) {
  DEBUG("STRING-SET!");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fa = frame[ra];
  auto fb = frame[rb];
  auto fc = frame[rc];
  if (unlikely((fa & 0x7) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (unlikely((fb&TAG_MASK) != FIXNUM_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (unlikely((fc&IMMEDIATE_MASK) != CHAR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto str = (string_s*)(fa-PTR_TAG);
  if (unlikely(str->type != STRING_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  str->str[fb >> 3] = (fc >> 8)&0xff;

  pc++;
  NEXT_INSTR;
}

void INS_SET_CAR(PARAMS) {
  DEBUG("SET-CAR!");
  unsigned char rb = instr & 0xff;

  auto fa = frame[ra];
  auto fb = frame[rb];
  if (unlikely((fa & 0x7) != CONS_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto cons = (cons_s*)(fa-CONS_TAG);
  cons->a = fb;

  pc++;
  NEXT_INSTR;
}

void INS_SET_CDR(PARAMS) {
  DEBUG("SET-CDR!");
  unsigned char rb = instr & 0xff;

  auto fa = frame[ra];
  auto fb = frame[rb];
  if (unlikely((fa & 0x7) != CONS_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto cons = (cons_s*)(fa-CONS_TAG);
  cons->b = fb;

  pc++;
  NEXT_INSTR;
}

void INS_WRITE(PARAMS) {
  DEBUG("WRITE");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr>>8) & 0xff;
  auto fb = frame[rb];
  auto fc = frame[rc];

  if (unlikely((fc&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto port = (port_s*)(fc-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }

  print_obj(fb, port->file);
  
  pc++;
  NEXT_INSTR;
}

void INS_WRITE_U8(PARAMS) {
  DEBUG("WRITE_U8");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr>>8) & 0xff;
  auto fb = frame[rb];
  auto fc = frame[rc];

  if (unlikely((fc&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto port = (port_s*)(fc-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (unlikely((fb&TAG_MASK) != FIXNUM_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  long byte = fb >> 3;
  unsigned char b = byte;
  if (unlikely(byte >= 256)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  
  fwrite(&b, 1, 1, port->file);
  
  pc++;
  NEXT_INSTR;
}

void INS_APPLY(PARAMS) {
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

void INS_SYMBOL_STRING(PARAMS) {
  DEBUG("SYMBOL_STRING");
  unsigned char rb = instr & 0xff;

  auto fb = frame[rb];
  if (unlikely((fb&TAG_MASK) != SYMBOL_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto sym = (symbol*)(fb - SYMBOL_TAG);
  frame[ra] = (long)sym->name + PTR_TAG;

  pc++;
  NEXT_INSTR;
}

void INS_STRING_SYMBOL(PARAMS) {
  DEBUG("STRING->SYMBOL");
  unsigned char rb = instr & 0xff;

  auto fb = frame[rb];
  if (unlikely((fb&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto str = (string_s*)(fb-PTR_TAG);
  if (unlikely(str->type != STRING_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto res = symbol_table_find(str);
  if (!res) {
    // Build a new symbol.
    // Must dup the string, since strings are not immutable.
    
    auto sym = (symbol *)GC_malloc(sizeof(symbol));
    auto str2 = from_c_str(str->str);
    auto str2p = (string_s*)(str2-PTR_TAG);
    sym->name = str2p;
    sym->val = UNDEFINED_TAG;
    symbol_table_insert(sym);
    
    frame[ra] = (long)sym + SYMBOL_TAG;
  } else {
    frame[ra] = (long)res + SYMBOL_TAG;
  }

  pc++;
  NEXT_INSTR;
}

void INS_CHAR_INTEGER(PARAMS) {
  DEBUG("CHAR->INTEGER");
  unsigned char rb = instr & 0xff;

  auto fb = frame[rb];
  if (unlikely((fb&IMMEDIATE_MASK) != CHAR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = fb >> 5;

  pc++;
  NEXT_INSTR;
}

void INS_INTEGER_CHAR(PARAMS) {
  DEBUG("INTEGER->CHAR");
  unsigned char rb = instr & 0xff;

  auto fb = frame[rb];
  if (unlikely((fb&TAG_MASK) != FIXNUM_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = (fb << 5) + CHAR_TAG;

  pc++;
  NEXT_INSTR;
}

void INS_DIV(PARAMS) {
  DEBUG("DIV");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fb = frame[rb];
  auto fc = frame[rc];
  if (likely((7 & (fb | fc)) == 0)) {
    frame[ra] = (fb/fc) << 3;
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {
    auto f1 = (flonum_s*)(fb-FLONUM_TAG);
    auto f2 = (flonum_s*)(fc-FLONUM_TAG);
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));
    r->x = f1->x / f2->x;
    frame[ra] = (long)r|FLONUM_TAG;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  pc++;

  NEXT_INSTR;
}

void INS_REM(PARAMS) {
  DEBUG("REM");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fb = frame[rb];
  auto fc = frame[rc];
  if (likely((7 & (fb | fc)) == 0)) {
    frame[ra] = ((fb >>3 ) % (fc >> 3)) << 3;
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {
    auto f1 = (flonum_s*)(fb-FLONUM_TAG);
    auto f2 = (flonum_s*)(fc-FLONUM_TAG);
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));
    r->x = remainder(f1->x, f2->x);
    frame[ra] = (long)r|FLONUM_TAG;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  pc++;

  NEXT_INSTR;
}

void INS_CALLCC(PARAMS) {
  DEBUG("CALLCC");
  
  auto sz = frame-stack;
  auto cont = (vector_s*)GC_malloc(sz*sizeof(long) + 16);
  cont->type = CONT_TAG;
  cont->len = sz;
  memcpy(cont->v, stack, sz*sizeof(long));

  frame[ra] = (long)cont | PTR_TAG;

  pc++;
  NEXT_INSTR;
}

void INS_CALLCC_RESUME(PARAMS) {
  DEBUG("CALLCC");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;

  auto fb = frame[rb];
  auto fc = frame[rc];
  if (unlikely((fb&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto cont = (vector_s*)(fb-PTR_TAG);
  if (unlikely(cont->type != CONT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  memcpy(stack, cont->v, cont->len*sizeof(long));
  frame = &stack[cont->len];
  
  frame[ra] = (long)cont | PTR_TAG;

  // DO A RET
  pc = (unsigned int *)frame[-1];
  frame[-1] = fc;
  frame -= (INS_A(*(pc - 1)) + 1);

  NEXT_INSTR;
}

void INS_OPEN(PARAMS) {
  DEBUG("OPEN");
  auto  rb = instr&0xff;
  auto  rc = (instr>>8)&0xff;

  auto fb = frame[rb];
  auto fc = frame[rc];
  if (unlikely((fc&IMMEDIATE_MASK) != BOOL_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }

  auto port = (port_s*)GC_malloc(sizeof(port_s));
  port->type = PORT_TAG;
  port->input_port = fc;

  if ((fb&TAG_MASK) == FIXNUM_TAG) {
    port->fd = frame[rb] >>3; 
  } else if ((fb&TAG_MASK) == PTR_TAG) {
    auto str = (string_s*)(fb - PTR_TAG);
    if (unlikely(str->type != STRING_TAG)) {
      MUSTTAIL return FAIL_SLOWPATH(ARGS);
    }
    port->fd = open(str->str, fc == TRUE_REP? O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (port->fd == -1) {
      printf("Could not open fd for file %s\n", str->str);
      exit(-1);
    }
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  port->file = fdopen(port->fd, fc == TRUE_REP ? "r" : "w");
  if (port->file == nullptr) {
    printf("FDopen fail\n");
    exit(-1);
  }
  port->peek = FALSE_REP;
  frame[ra] = (long)port + PTR_TAG;
  pc++;

  NEXT_INSTR;
}

void INS_CLOSE(PARAMS) {
  DEBUG("CLOSE");
  auto  rb = instr&0xff;

  auto fb = frame[rb];
  if (unlikely((fb&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto port = (port_s*)(fb-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (port->file) {
    fclose(port->file);
    port->file = nullptr;
  }
  if (port->fd != -1) {
    close(port->fd);
    port->fd = -1;
  }

  pc++;

  NEXT_INSTR;
}

void INS_PEEK(PARAMS) {
  DEBUG("PEEK");
  auto  rb = instr&0xff;

  auto fb = frame[rb];
  if (unlikely((fb&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto port = (port_s*)(fb-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (port->peek != FALSE_REP) {
  } else {
    uint8_t b;
    long res = fread(&b, 1, 1, port->file);
    if (res == 0) {
      port->peek = EOF_TAG;
    } else {
      port->peek = (((long)b) << 8) + CHAR_TAG;
    }
  }
  frame[ra] = port->peek;

  pc++;

  NEXT_INSTR;
}

void INS_READ(PARAMS) {
  DEBUG("READ");
  auto  rb = instr&0xff;

  auto fb = frame[rb];
  if (unlikely((fb&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto port = (port_s*)(fb-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  if (port->peek != FALSE_REP) {
    frame[ra] = port->peek;
    port->peek = FALSE_REP;
  } else {
    uint8_t b;
    long res = fread(&b, 1, 1, port->file);
    if (res == 0) {
      frame[ra] = EOF_TAG;
    } else {
      frame[ra] = (((long)b) << 8) + CHAR_TAG;
    }
  }

  pc++;

  NEXT_INSTR;
}

void INS_UNKNOWN(PARAMS) {
  printf("UNIMPLEMENTED INSTRUCTION %s\n", ins_names[INS_OP(*pc)]);
  exit(-1);
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
  l_op_table[CLOSURE] = INS_CLOSURE; 
  l_op_table[CLOSURE_PTR] = INS_CLOSURE_PTR; 
  l_op_table[CLOSURE_GET] = INS_CLOSURE_GET; 
  l_op_table[CLOSURE_SET] = INS_CLOSURE_SET; 
  l_op_table[EQ] = INS_EQ; 
  l_op_table[CONS] = INS_CONS; 
  l_op_table[CAR] = INS_CAR; 
  l_op_table[CDR] = INS_CDR; 
  l_op_table[MAKE_VECTOR] = INS_MAKE_VECTOR; 
  l_op_table[VECTOR_REF] = INS_VECTOR_REF; 
  l_op_table[VECTOR_SET] = INS_VECTOR_SET; 
  l_op_table[VECTOR_LENGTH] = INS_VECTOR_LENGTH; 
  l_op_table[SET_CAR] = INS_SET_CAR; 
  l_op_table[SET_CDR] = INS_SET_CDR; 
  l_op_table[WRITE] = INS_WRITE; 
  l_op_table[WRITE_U8] = INS_WRITE_U8; 
  l_op_table[STRING_LENGTH] = INS_STRING_LENGTH; 
  l_op_table[STRING_REF] = INS_STRING_REF; 
  l_op_table[STRING_SET] = INS_STRING_SET; 
  l_op_table[MAKE_STRING] = INS_MAKE_STRING; 
  l_op_table[APPLY] = INS_APPLY; 
  l_op_table[SYMBOL_STRING] = INS_SYMBOL_STRING; 
  l_op_table[STRING_SYMBOL] = INS_STRING_SYMBOL; 
  l_op_table[CHAR_INTEGER] = INS_CHAR_INTEGER; 
  l_op_table[INTEGER_CHAR] = INS_INTEGER_CHAR; 
  l_op_table[REM] = INS_REM; 
  l_op_table[DIV] = INS_DIV; 
  l_op_table[CALLCC] = INS_CALLCC; 
  l_op_table[CALLCC_RESUME] = INS_CALLCC_RESUME; 
  l_op_table[OPEN] = INS_OPEN; 
  l_op_table[CLOSE] = INS_CLOSE; 
  l_op_table[READ] = INS_READ; 
  l_op_table[PEEK] = INS_PEEK; 
  l_op_table[JEQ] = INS_JEQ; 
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
