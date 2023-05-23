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

#define LIBRARY_FUNC_BC(name) ABI void INS_##name(PARAMS) { \
  DEBUG(#name);						    \
  unsigned char rb = instr & 0xff;			    \
  unsigned char rc = (instr >> 8) & 0xff;		    
#define LIBRARY_FUNC_BC_LOAD(name) LIBRARY_FUNC_BC(name) \
  long fb = frame[rb];					    \
  long fc = frame[rc];
#define LIBRARY_FUNC_B(name) ABI void INS_##name(PARAMS) {	\
  DEBUG(#name);						    \
  unsigned char rb = instr & 0xff;			    
#define LIBRARY_FUNC_D(name) ABI void INS_##name(PARAMS) {	\
  DEBUG(#name);						    \
  auto rd = (int16_t)instr;
#define LIBRARY_FUNC(name) ABI void INS_##name(PARAMS) {	\
  DEBUG(#name);						    
#define LIBRARY_FUNC_B_LOAD(name) LIBRARY_FUNC_B(name) \
  long fb = frame[rb];					    
#define LIBRARY_FUNC_B_LOAD_NAME(str, name) LIBRARY_FUNC_B_LOAD(name)
#define LIBRARY_FUNC_BC_LOAD_NAME(str, name) LIBRARY_FUNC_BC_LOAD(name)
#define LIBRARY_FUNC_BC_NAME(str, name) LIBRARY_FUNC_BC(name)
#define END_LIBRARY_FUNC pc++;NEXT_INSTR; }

#define TYPECHECK_TAG(val,tag)			\
  if(unlikely((val&TAG_MASK) != tag)) {		\
    MUSTTAIL return FAIL_SLOWPATH(ARGS);	\
  }
#define TYPECHECK_FIXNUM(val) TYPECHECK_TAG(val, FIXNUM_TAG)

LIBRARY_FUNC_B(FUNC)
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
END_LIBRARY_FUNC

LIBRARY_FUNC_D(KSHORT)
  frame[ra] = rd << 3;
END_LIBRARY_FUNC

LIBRARY_FUNC_D(JMP)
  pc += rd;
  NEXT_INSTR;
}

LIBRARY_FUNC(RET1)
  pc = (unsigned int *)frame[-1];
  frame[-1] = frame[ra];
  frame -= (INS_A(*(pc - 1)) + 1);

  NEXT_INSTR;
}

LIBRARY_FUNC(HALT)
  return;
}

// Note signed-ness of rc.
#define LIBRARY_FUNC_MATH_VN(name, op)		\
  LIBRARY_FUNC_B(name)				\
   char rc = (instr >> 8) & 0xff;		\
   long fb = frame[rb];				\
   TYPECHECK_TAG(fb, FIXNUM_TAG);		\
   if (unlikely(__builtin_##op##_overflow(fb, (rc << 3), &frame[ra]))) {	\
     MUSTTAIL return FAIL_SLOWPATH(ARGS);				\
   }									\
END_LIBRARY_FUNC

LIBRARY_FUNC_MATH_VN(SUBVN, sub);
LIBRARY_FUNC_MATH_VN(ADDVN, add);

#define OVERFLOW_OP(op, name, shift)					\
if (unlikely(__builtin_##op##_overflow(fb, fc >> shift, &frame[ra]))) { \
  MUSTTAIL return INS_##name##_SLOWPATH(ARGS);				\
}									

// Shift is necessary for adjusting the tag for mul.
#define LIBRARY_FUNC_MATH_VV(name, op2, overflow)		\
ABI __attribute__((noinline)) void INS_##name##_SLOWPATH(PARAMS) {	\
  DEBUG(#name);								\
  unsigned char rb = instr & 0xff;					\
  unsigned char rc = (instr >> 8) & 0xff;				\
									\
  auto fb = frame[rb];							\
  auto fc = frame[rc];							\
  double x_b;								\
  double x_c;								\
  if ((fb&TAG_MASK) == FLONUM_TAG) {					\
    x_b = ((flonum_s*)(fb-FLONUM_TAG))->x;				\
  } else if ((fb&TAG_MASK) == FIXNUM_TAG) {				\
    x_b = fb >> 3;							\
  } else {								\
    MUSTTAIL return FAIL_SLOWPATH(ARGS);				\
  }									\
  if ((fc&TAG_MASK) == FLONUM_TAG) {					\
    x_c = ((flonum_s*)(fc-FLONUM_TAG))->x;				\
  } else if ((fc&TAG_MASK) == FIXNUM_TAG) {				\
    x_c = fc >> 3;							\
  } else {								\
    MUSTTAIL return FAIL_SLOWPATH(ARGS);				\
  }									\
									\
  auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));			\
  r->x = op2(x_b, x_c);							\
  r->type = FLONUM_TAG;							\
  frame[ra] = (long)r|FLONUM_TAG;					\
  pc++;									\
									\
  NEXT_INSTR;								\
}									\
									\
 LIBRARY_FUNC_BC_LOAD(name)						\
  if (likely((7 & (fb | fc)) == 0)) {					\
    overflow;								\
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {		\
    auto x_b = ((flonum_s*)(fb-FLONUM_TAG))->x;				\
    auto x_c = ((flonum_s*)(fc-FLONUM_TAG))->x;				\
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));			\
    r->x = op2(x_b, x_c);						\
    r->type = FLONUM_TAG;						\
    frame[ra] = (long)r|FLONUM_TAG;					\
  } else {								\
    MUSTTAIL return INS_##name##_SLOWPATH(ARGS);			\
  }									\
END_LIBRARY_FUNC							

#define LIBRARY_FUNC_MATH_OVERFLOW_VV(name, op, op2, shift)		\
  LIBRARY_FUNC_MATH_VV(name, op2, OVERFLOW_OP(op, name, shift));

#define MATH_ADD(a, b) (a+b)
#define MATH_SUB(a, b) (a-b)
#define MATH_MUL(a, b) (a*b)
#define MATH_DIV(a, b) (a/b)

LIBRARY_FUNC_MATH_OVERFLOW_VV(ADDVV,add,MATH_ADD, 0);
LIBRARY_FUNC_MATH_OVERFLOW_VV(SUBVV,sub, MATH_SUB, 0);
LIBRARY_FUNC_MATH_OVERFLOW_VV(MULVV,mul, MATH_MUL, 3);
LIBRARY_FUNC_MATH_VV(DIV, MATH_DIV, frame[ra] = (fb/fc) << 3);
LIBRARY_FUNC_MATH_VV(REM, remainder, frame[ra] = ((fb>>3)%(fc>>3)) << 3);

LIBRARY_FUNC_BC_LOAD(JEQ)
  if (fb == fc) {
    pc += 2;
  } else {
    pc += 1;
  }

  NEXT_INSTR;
}

#define LIBRARY_FUNC_NUM_CMP(name, op, func)		\
  LIBRARY_FUNC_BC_LOAD(name##_SLOWPATH)         \
  double x_b;					\
  double x_c;					\
  if ((fb&TAG_MASK) == FLONUM_TAG) {		\
    x_b = ((flonum_s*)(fb-FLONUM_TAG))->x;	\
  } else if ((fb&TAG_MASK) == FIXNUM_TAG) {	\
    x_b = fb >> 3;				\
  } else {					\
    MUSTTAIL return FAIL_SLOWPATH(ARGS);	\
  }						\
  if ((fc&TAG_MASK) == FLONUM_TAG) {		\
    x_c = ((flonum_s*)(fc-FLONUM_TAG))->x;	\
  } else if ((fc&TAG_MASK) == FIXNUM_TAG) {	\
    x_c = fc >> 3;				\
  } else {					\
    MUSTTAIL return FAIL_SLOWPATH(ARGS);	\
  }						\
						\
  func(x_b, x_c, op);			\
						\
  NEXT_INSTR;					\
}						\
 LIBRARY_FUNC_BC_LOAD(name)			\
  if (likely((7 & (fb | fc)) == 0)) {		\
    func(fb, fc, op);			\
  } else if (likely(((7&fb) == (7&fc)) && ((7&fc) == 2))) {	\
    auto x_b = ((flonum_s*)(fb-FLONUM_TAG))->x;			\
    auto x_c = ((flonum_s*)(fc-FLONUM_TAG))->x;			\
    func(x_b, x_c, op);					\
  } else {							\
    MUSTTAIL return INS_##name##_SLOWPATH(ARGS);		\
  }								\
								\
  NEXT_INSTR;							\
}

#define MOVE_PC(a, b, op)			\
  if(a op b) {					\
    pc += 2;					\
  } else {					\
    pc += 1;					\
  }

#define SET_RES(a, b, op)			\
  if(a op b) {					\
    frame[ra] = TRUE_REP;			\
  } else {					\
    frame[ra] = FALSE_REP;			\
  }						\
  pc++;

LIBRARY_FUNC_NUM_CMP(JISLT, <, MOVE_PC);
LIBRARY_FUNC_NUM_CMP(JISEQ, ==, MOVE_PC);
LIBRARY_FUNC_NUM_CMP(ISLT, <, SET_RES);
LIBRARY_FUNC_NUM_CMP(ISEQ, ==, SET_RES);

LIBRARY_FUNC_B_LOAD(ISF)
  if (fb == FALSE_REP) {
    pc += 1;
  } else {
    pc += 2;
  }

  NEXT_INSTR;
}


LIBRARY_FUNC_D(GGET)
  symbol *gp = (symbol *)(const_table[rd] - SYMBOL_TAG);
  if (unlikely(gp->val == UNDEFINED_TAG)) {
    MUSTTAIL return UNDEFINED_SYMBOL_SLOWPATH(ARGS);
  }
  frame[ra] = gp->val;
END_LIBRARY_FUNC

LIBRARY_FUNC_D(GSET)
  symbol *gp = (symbol *)(const_table[rd] - SYMBOL_TAG);
  gp->val = frame[ra];
END_LIBRARY_FUNC

LIBRARY_FUNC_D(KFUNC)
  frame[ra] = (long)funcs[rd];
END_LIBRARY_FUNC

LIBRARY_FUNC_D(KONST)
  frame[ra] = const_table[rd];
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(MOV)
  frame[ra] = fb;
END_LIBRARY_FUNC

LIBRARY_FUNC_B(BOX)
  auto box = (cons_s*)GC_malloc(sizeof(cons_s));
  
  box->type = CONS_TAG;
  box->a = frame[rb];
  box->b = NIL_TAG;
  frame[ra] = (long)box|PTR_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(UNBOX)
  auto box = (cons_s*)(fb - PTR_TAG);
  frame[ra] = box->a;
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(SET-BOX!, SET_BOX)
  auto box = (cons_s*)(fb - PTR_TAG);
  box->a = fc;
END_LIBRARY_FUNC

LIBRARY_FUNC_BC(GUARD)
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
END_LIBRARY_FUNC

LIBRARY_FUNC_B(CLOSURE)
  auto closure = (closure_s*)GC_malloc(sizeof(long)*(rb + 2));
  closure->type = CLOSURE_TAG;
  closure->len = rb;
  for(int i = 0; i < rb; i++) {
    closure->v[i] = frame[ra + i];
  }
  frame[ra] = (long)closure|CLOSURE_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_NAME(CLOSURE-GET, CLOSURE_GET)
  auto fb = frame[rb];
  TYPECHECK_TAG(fb, CLOSURE_TAG);
  auto closure = (closure_s*)(fb-CLOSURE_TAG);
  frame[ra] = closure->v[1 + rc];
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_NAME(CLOSURE-SET, CLOSURE_SET)
  auto fa = frame[ra];
  // No need to typecheck, that would be bad bytecode.
  auto closure = (closure_s*)(fa-CLOSURE_TAG);
  closure->v[1 + rc] = frame[rb];
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(CLOSURE-PTR, CLOSURE_PTR)
  TYPECHECK_TAG(fb, CLOSURE_TAG);
  auto closure = (closure_s*)(fb-CLOSURE_TAG);
  frame[ra] = closure->v[0];
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD(APPLY)
  if (unlikely((fb & 0x7) != CLOSURE_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  // TODO check type NIL

  long a = 0;
  for(;(fc&TAG_MASK) == CONS_TAG;a++) {
    auto cons = (cons_s*)(fc-CONS_TAG);
    frame[a+1] = cons->a;
    fc = cons->b;
  }
  frame[0] = fb;
  auto clo = (closure_s*)(fb-CLOSURE_TAG);
  auto func = (bcfunc*)clo->v[0];
  pc = &func->code[0];
  argcnt = a+1;

  NEXT_INSTR;
}

LIBRARY_FUNC(JFUNC)
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

#define LIBRARY_FUNC_COPY(name, copied)
LIBRARY_FUNC_COPY(JLOOP, JFUNC);
#define INS_JLOOP INS_JFUNC

LIBRARY_FUNC_B(CALL)
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

LIBRARY_FUNC_B(CALLT)
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

LIBRARY_FUNC_BC_LOAD(EQ) 
  if (fb == fc) {
    frame[ra] = TRUE_REP;
  } else {
    frame[ra] = FALSE_REP;
  }
END_LIBRARY_FUNC

LIBRARY_FUNC_BC(CONS)
  auto c = (cons_s *)GC_malloc(sizeof(cons_s));

  c->type = CONS_TAG;
  c->a = frame[rb];
  c->b = frame[rc];

  frame[ra] = (long)c|CONS_TAG;
END_LIBRARY_FUNC

#define LIBRARY_FUNC_CONS_OP(name, field)			\
 LIBRARY_FUNC_B_LOAD(name)			\
  TYPECHECK_TAG(fb, CONS_TAG);			\
  auto c = (cons_s*)(fb-CONS_TAG);		\
  frame[ra] = c->field;				\
END_LIBRARY_FUNC

LIBRARY_FUNC_CONS_OP(CAR,a);
LIBRARY_FUNC_CONS_OP(CDR,b);

LIBRARY_FUNC_BC_NAME(MAKE-VECTOR, MAKE_VECTOR)
  long fb = frame[rb];
  TYPECHECK_FIXNUM(fb);

  auto len = fb>>3;
  auto vec = (vector_s*)GC_malloc( sizeof(long) * (len + 2));
  // Load frame[rc] *after* GC
  long fc = frame[rc];
  vec->type = VECTOR_TAG;
  vec->len = len;
  for(long i = 0; i < len; i++) {
    vec->v[i] = fc;
  }
  
  frame[ra] = (long)vec | PTR_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_NAME(MAKE-STRING, MAKE_STRING)
  long fb = frame[rb];
  TYPECHECK_FIXNUM(fb);
  auto len = fb>>3;
  auto str = (string_s*)GC_malloc( (sizeof(long) * 2) + len + 1);
  
  long fc = frame[rc]; // Load fc after GC
  if(unlikely((fc&IMMEDIATE_MASK) != CHAR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  
  str->type = STRING_TAG;
  str->len = len;
  for(long i = 0; i < len; i++) {
    str->str[i] = (fc >> 8)&0xff;
  }
  str->str[len] = '\0';
  
  frame[ra] = (long)str | PTR_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(VECTOR-REF, VECTOR_REF)
  TYPECHECK_FIXNUM(fc);
  TYPECHECK_TAG(fb, PTR_TAG);
  auto vec = (vector_s*)(fb-PTR_TAG);
  if (unlikely(vec->type != VECTOR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = vec->v[fc>>3];
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(STRING-REF, STRING_REF)
  TYPECHECK_FIXNUM(fc);
  TYPECHECK_TAG(fb, PTR_TAG);
  auto str = (string_s*)(fb-PTR_TAG);
  if (unlikely(str->type != STRING_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = (str->str[fc>>3] << 8)|CHAR_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(VECTOR-LENGTH, VECTOR_LENGTH)
  TYPECHECK_TAG(fb, PTR_TAG);
  auto vec = (vector_s*)(fb-PTR_TAG);
  if (unlikely(vec->type != VECTOR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = vec->len << 3;
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(STRING-LENGTH, STRING_LENGTH)
  TYPECHECK_TAG(fb, PTR_TAG);
  auto str = (string_s*)(fb-PTR_TAG);
  if (unlikely(str->type != STRING_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = str->len << 3;
END_LIBRARY_FUNC
  
LIBRARY_FUNC_BC_LOAD_NAME(VECTOR-SET!, VECTOR_SET)
  auto fa = frame[ra];
  TYPECHECK_FIXNUM(fb);
  TYPECHECK_TAG(fa, PTR_TAG);
  auto vec = (vector_s*)(fa-PTR_TAG);
  if (unlikely(vec->type != VECTOR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  vec->v[fb >> 3] = fc;
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(STRING-SET!, STRING_SET)
  auto fa = frame[ra];
  if (unlikely((fa&TAG_MASK) != PTR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  TYPECHECK_FIXNUM(fb);
  if (unlikely((fc&IMMEDIATE_MASK) != CHAR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto str = (string_s*)(fa-PTR_TAG);
  if (unlikely(str->type != STRING_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  str->str[fb >> 3] = (fc >> 8)&0xff;
END_LIBRARY_FUNC

#define LIBRARY_FUNC_CONS_SET_OP(str, name, field)	\
  LIBRARY_FUNC_B_LOAD_NAME(str, name)			\
  auto fa = frame[ra];				\
  TYPECHECK_TAG(fa, CONS_TAG);			\
  auto cons = (cons_s*)(fa-CONS_TAG);		\
  cons->field = fb;				\
END_LIBRARY_FUNC

LIBRARY_FUNC_CONS_SET_OP(SET-CAR!, SET_CAR,a);
LIBRARY_FUNC_CONS_SET_OP(SET-CDR!, SET_CDR,b);

LIBRARY_FUNC_BC_LOAD(WRITE)
  TYPECHECK_TAG(fc, PTR_TAG);
  auto port = (port_s*)(fc-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }

  print_obj(fb, port->file);
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(WRITE-U8, WRITE_U8)
  TYPECHECK_TAG(fc, PTR_TAG);
  auto port = (port_s*)(fc-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  TYPECHECK_FIXNUM(fb);
  long byte = fb >> 3;
  unsigned char b = byte;
  if (unlikely(byte >= 256)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  
  fwrite(&b, 1, 1, port->file);
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(WRITE-DOUBLE, WRITE_DOUBLE)
  TYPECHECK_TAG(fc, PTR_TAG);
  auto port = (port_s*)(fc-PTR_TAG);
  if (unlikely(port->type != PORT_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  TYPECHECK_TAG(fb, FLONUM_TAG);
  auto flo = (flonum_s*)(fb - FLONUM_TAG);
  
  fwrite(&flo->x, sizeof(flo->x), 1, port->file);
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(SYMBOL->STRING, SYMBOL_STRING)
  TYPECHECK_TAG(fb, SYMBOL_TAG);
  auto sym = (symbol*)(fb - SYMBOL_TAG);
  frame[ra] = (long)sym->name + PTR_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(STRING->SYMBOL, STRING_SYMBOL)
  TYPECHECK_TAG(fb, PTR_TAG);
  auto str = (string_s*)(fb-PTR_TAG);
  if (unlikely(str->type != STRING_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  auto res = symbol_table_find(str);
  if (!res) {
    // Build a new symbol.
    // Must dup the string, since strings are not immutable.
    auto strlen = str->len;
    auto sym = (symbol *)GC_malloc(sizeof(symbol));
    sym->type = SYMBOL_TAG;

    // Note re-load of str after allocation.
    sym->name = (string_s*)(frame[rb]-PTR_TAG);
    sym->val = UNDEFINED_TAG;

    // Save new symbol in frame[ra].
    frame[ra] = (long)sym + SYMBOL_TAG;
    
    // DUP the string, so that this one is immutable.
    // Note that original is in sym->name temporarily
    // since ra could be eq to rb.
    auto str2 = (string_s*)GC_malloc(16 + strlen + 1);
    // Re-load sym after GC
    sym = (symbol*)(frame[ra]-SYMBOL_TAG);
    
    // Re-load str after GC
    str = (string_s*)sym->name;
    
    str2->type = STRING_TAG;
    str2->len = strlen;
    memcpy(str2->str, str->str, strlen);
    
    sym->name = str2;
    symbol_table_insert(sym);
  } else {
    frame[ra] = (long)res + SYMBOL_TAG;
  }
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(CHAR->INTEGER, CHAR_INTEGER)
  if (unlikely((fb&IMMEDIATE_MASK) != CHAR_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = fb >> 5;
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME(INTEGER->CHAR, INTEGER_CHAR)
  TYPECHECK_FIXNUM(fb);
  frame[ra] = (fb << 5) + CHAR_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_BC(OPEN)
  auto fc = frame[rc];
  if (unlikely((fc&IMMEDIATE_MASK) != BOOL_TAG)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }

  auto port = (port_s*)GC_malloc(sizeof(port_s));
  // Load FB (potentially a ptr) after GC
  auto fb = frame[rb];
  
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
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(CLOSE)
  TYPECHECK_TAG(fb, PTR_TAG);
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
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(PEEK)
  TYPECHECK_TAG(fb, PTR_TAG);
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
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(READ)
  TYPECHECK_TAG(fb, PTR_TAG);
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
END_LIBRARY_FUNC
  
LIBRARY_FUNC_B_LOAD(INEXACT)
  if ((fb&TAG_MASK) == FIXNUM_TAG) {
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));
    r->type = FLONUM_TAG;
    r->x = fb>>3;
    frame[ra] = (long)r + FLONUM_TAG;
  } else if ((fb&TAG_MASK) == FLONUM_TAG) {
    frame[ra] = fb;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(EXACT)
  if ((fb&TAG_MASK) == FIXNUM_TAG) {
    frame[ra] = fb;
  } else if ((fb&TAG_MASK) == FLONUM_TAG) {
    auto flo = (flonum_s*)(fb - FLONUM_TAG);
    frame[ra] = ((long)flo->x) << 3;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(ROUND)
  if ((fb&TAG_MASK) == FIXNUM_TAG) {
    frame[ra]  =fb;
  } else if ((fb&TAG_MASK) == FLONUM_TAG) {
    auto flo = (flonum_s*)(fb - FLONUM_TAG);
    auto res = roundeven(flo->x);
    
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));
    r->type = FLONUM_TAG;
    r->x = res;
    frame[ra] = (long)r + FLONUM_TAG;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
END_LIBRARY_FUNC

#define LIBRARY_FUNC_FLONUM_MATH(name, func)	\
  LIBRARY_FUNC_B_LOAD(name)			\
  if ((fb&TAG_MASK) == FLONUM_TAG) {		\
    auto flo = (flonum_s*)(fb - FLONUM_TAG);	\
    auto res = func(flo->x);				\
							\
    auto r = (flonum_s*)GC_malloc(sizeof(flonum_s));	\
    r->type = FLONUM_TAG;				\
    r->x = res;						\
    frame[ra] = (long)r + FLONUM_TAG;			\
  } else {						\
    MUSTTAIL return FAIL_SLOWPATH(ARGS);		\
  }							\
END_LIBRARY_FUNC

LIBRARY_FUNC_FLONUM_MATH(SIN, sin);
LIBRARY_FUNC_FLONUM_MATH(SQRT, sqrt);
LIBRARY_FUNC_FLONUM_MATH(ATAN, atan);
LIBRARY_FUNC_FLONUM_MATH(COS, cos);

LIBRARY_FUNC(CALLCC)
  auto sz = frame-stack;
  auto cont = (vector_s*)GC_malloc(sz*sizeof(long) + 16);
  cont->type = CONT_TAG;
  cont->len = sz;
  memcpy(cont->v, stack, sz*sizeof(long));

  frame[ra] = (long)cont | PTR_TAG;
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME(CALLCC-RESUME, CALLCC_RESUME)
  TYPECHECK_TAG(fb, PTR_TAG);
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

//////////////

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
