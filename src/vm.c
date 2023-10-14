#include "vm.h"

#include <assert.h>  // for assert
#include <fcntl.h>   // for open, O_CREAT, O_RDONLY, O_TRUNC
#include <math.h>    // for remainder, acos, asin, atan, ceil, cos
#include <stdbool.h> // for bool, false, true
#include <stdio.h>   // for printf, fread, fwrite, fclose, fdopen
#include <stdlib.h>  // for exit, realloc, free, malloc
#include <string.h>  // for memcpy, NULL, memset
#include <unistd.h>  // for access, close, unlink, F_OK
#ifdef AFL
#include <nmmintrin.h>
#endif

#include "asm_x64.h"
#include "bytecode.h"
#include "defs.h"
#include "gc.h"
#include "opcodes.h"
#include "record.h"
#ifdef PROFILER
#include "profiler.h"
#endif
#include "ir.h"
#include "symbol_table.h"
#include "types.h"

#include "third-party/stb_ds.h"

#define NO_LINT                                                                \
  __attribute__((annotate("oclint:suppress[parameter reassignment]")))

EXPORT bool verbose = false;
EXPORT unsigned TRACE_MAX = 65535;
EXPORT int joff = 0;
EXPORT int profile = 0;

#define IN_BUFFER_SZ 4096

bcfunc **funcs = NULL;
#define auto __auto_type
#ifdef AFL
void __afl_trace(const uint32_t x);
static void afl_trace(uint32_t *pc) {
  int64_t start = _mm_crc32_u64(0, (uint64_t)pc) & ((1LL << 16) - 1);
  __afl_trace(start);
}
#else

static void afl_trace(uint32_t *pc) {} //!OCLINT
#endif

gc_obj *frame_top;
unsigned int stacksz = 100;
gc_obj *stack_top;
gc_obj *stack = NULL;

unsigned char hotmap[hotmap_sz];

static inline uint32_t hotmap_hash(const uint32_t *pc) {
  return (((uint64_t)pc) >> 2) & hotmap_mask;
}

static void vm_init() {
  if (stack == NULL) {
    stack = (long *)malloc(sizeof(long) * stacksz);
    stack_top = stack;
    memset(stack, 0, sizeof(long) * stacksz);
  }
}

EXPORT void free_vm() { free(stack); }

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
#define DEBUG_VM(name)
/* #define DEBUG_VM(name) \ */
/*   printf("pc %p %s ra %i rd %i rb %i rc %i\n", pc, name, ra, instr, \ */
/*          instr & 0xff, (instr >> 8)); \ */
/*   fflush(stdout); */
typedef void (*op_func)(PARAMS); //!OCLINT
static op_func l_op_table[INS_MAX];
static op_func l_op_table_record[INS_MAX];
#ifdef PROFILER
static op_func l_op_table_profile[INS_MAX];
#endif

#define NEXT_INSTR                                                             \
  {                                                                            \
    instr = *pc;                                                               \
    unsigned char op = instr & 0xff;                                           \
    ra = (instr >> 8) & 0xff;                                                  \
    instr >>= 16;                                                              \
    op_func *op_table_arg_c = (op_func *)op_table_arg;                         \
    MUSTTAIL return op_table_arg_c[op](ARGS);                                  \
  }

bcfunc *find_func_for_frame(const uint32_t *pc) {
  for (unsigned long j = 0; j < arrlen(funcs); j++) {
    auto fun = funcs[j];
    if (pc >= &fun->code[0] && pc <= &fun->code[fun->codelen - 1]) {
      return fun;
    }
  }
  printf("Could not find func for frame: %p\n", pc);
  exit(-1);
}

NOINLINE void NO_LINT FAIL_SLOWPATH(PARAMS) { //!OCLINT
  int i = 0;
  printf("FAIL PC: %p %s\n", pc, ins_names[INS_OP(*pc)]);
  while (&frame[-1] > stack) {
    auto res = find_func_for_frame(pc);
    if (res) {
      printf("FUNC: %s PC %li\n", res->name, pc - &res->code[0]);
    }
    pc = (unsigned int *)frame[-1];
    frame[-1] = frame[ra];
    frame -= (INS_A(*(pc - 1)) + 1);
    printf("%i PC: %p\n", i++, pc);
  }
}

NOINLINE void FAIL_SLOWPATH_ARGCNT(PARAMS) {
  printf("FAIL ARGCNT INVALID calling %s given %li args takes %i\n",
         find_func_for_frame(pc)->name, argcnt, ra);

  MUSTTAIL return FAIL_SLOWPATH(ARGS);
}

void RECORD_START(PARAMS) {
  hotmap[hotmap_hash(pc)] = hotmap_cnt;
  // Extra check: we may have attempted to start recording *during*
  // a recording.
  if (joff || (op_table_arg == (void **)l_op_table_record)) {
    // Tail call with original op table.
    MUSTTAIL return l_op_table[INS_OP(*pc)](ARGS);
  }
  MUSTTAIL return l_op_table_record[INS_OP(*pc)](
      ra, instr, pc, frame, (void **)l_op_table_record, argcnt);
}

void NO_LINT RECORD(PARAMS) {
#ifdef JIT
  if (record(pc, frame, argcnt)) {
    // Back to interpreting.
    op_table_arg = (void **)l_op_table;
  }
#else
  op_table_arg = (void **)l_op_table;
#endif
  // record may have updated state.
  instr = *pc;
  ra = (instr >> 8) & 0xff;
  instr >>= 16;
  // Call interpret op table, but with record table.
  // Interprets *this* instruction, then advances to next
  MUSTTAIL return l_op_table[INS_OP(*pc)](ra, instr, pc, frame, op_table_arg,
                                          argcnt);
}

static gc_obj build_list(long start, long len, const long *frame) {
  gc_obj lst = NIL_TAG;
  // printf("Build list from %i len %i\n", start, len);
  for (long pos = start + len - 1; pos >= start; pos--) {
    GC_push_root(&lst); // TODO just save in POS instead?
    cons_s *c = GC_malloc(sizeof(cons_s));
    GC_pop_root(&lst); // TODO just save in POS instead?
    c->type = CONS_TAG;
    c->rc = 0;
    c->a = frame[pos];
    c->b = lst;
    lst = tag_cons(c);
  }

  return lst;
}

NOINLINE void UNDEFINED_SYMBOL_SLOWPATH(PARAMS) { //!OCLINT
  auto rd = instr;

  symbol *gp = (symbol *)(const_table[rd] - SYMBOL_TAG);

  string_s *sym_name = (string_s *)(gp->name - PTR_TAG);
  printf("FAIL undefined symbol: %s\n", sym_name->str);
}

void expand_stack(long **o_frame) {
  if (verbose) {
    printf("Expand stack from %u to %u\n", stacksz, stacksz * 2);
  }
  auto pos = *o_frame - stack;
  auto oldsz = stacksz;
  stacksz *= 2;
  auto stack_top_offset = stack_top - stack;
  stack = (long *)realloc(stack, stacksz * sizeof(long));
  if (!stack) {
    printf("Error: Could not realloc stack\n");
    exit(-1);
  }

  memset(&stack[oldsz], 0, sizeof(long) * (stacksz - oldsz));
  *o_frame = stack + pos;
  frame_top = stack + stacksz - 256;
  stack_top = stack + stack_top_offset;
}

NOINLINE void NO_LINT EXPAND_STACK_SLOWPATH(PARAMS) {
  expand_stack(&frame);

  NEXT_INSTR;
}

/* A whole pile of macros to make opcode generation easier.
 *
 * The B/BC/D refer to opcode type.  'NAME' refers to scm vs C name.
 *
 * Any line starting with "LIBRARY_FUNC" will auto-generate a
 * opcode number via opcode_gen.scm.  So macros generating
 * LIBRARY_FUNC are indented a space, to not generate numbers.
 *
 * Slow paths are split to their own tail-called functions,
 * to help out the register allocator.
 *
 * TODO: VN funcs don't have proper slowpath fallbacks for overflow.
 * TODO: most functions call FAIL_SLOWPATH without listing type
 *       of failure.  This is confusing and hard to debug.
 *       Maybe pass some info in argcnt param.
 */
#define LIBRARY_FUNC_BC(name)                                                  \
  void NO_LINT INS_##name(PARAMS) {                                            \
    DEBUG_VM(#name);                                                           \
    unsigned char rb = instr & 0xff;                                           \
    unsigned char rc = (instr >> 8) & 0xff;
#define LIBRARY_FUNC_BC_LOAD(name)                                             \
  LIBRARY_FUNC_BC(name)                                                        \
  long fb = frame[rb];                                                         \
  long fc = frame[rc];
#define LIBRARY_FUNC_B(name)                                                   \
  void NO_LINT INS_##name(PARAMS) {                                            \
    DEBUG_VM(#name);                                                           \
    unsigned char rb = instr & 0xff;
#define LIBRARY_FUNC_D(name)                                                   \
  void NO_LINT INS_##name(PARAMS) {                                            \
    DEBUG_VM(#name);                                                           \
    auto rd = (int16_t)instr;
#define LIBRARY_FUNC(name)                                                     \
  void NO_LINT INS_##name(PARAMS) {                                            \
    DEBUG_VM(#name);
#define LIBRARY_FUNC_B_LOAD(name)                                              \
  LIBRARY_FUNC_B(name)                                                         \
  long fb = frame[rb];
#define LIBRARY_FUNC_B_LOAD_NAME(str, name) LIBRARY_FUNC_B_LOAD(name)
#define LIBRARY_FUNC_BC_LOAD_NAME(str, name) LIBRARY_FUNC_BC_LOAD(name)
#define LIBRARY_FUNC_BC_NAME(str, name) LIBRARY_FUNC_BC(name)
#define NEXT_FUNC                                                              \
  NEXT_INSTR;                                                                  \
  }
#define END_LIBRARY_FUNC                                                       \
  pc++;                                                                        \
  NEXT_INSTR;                                                                  \
  }

#define TYPECHECK_TAG(val, tag)                                                \
  if (unlikely((get_tag(val)) != (tag))) {                                     \
    MUSTTAIL return FAIL_SLOWPATH(ARGS);                                       \
  }
#define TYPECHECK_FIXNUM(val) TYPECHECK_TAG(val, FIXNUM_TAG)
#define TYPECHECK_IMMEDIATE(val, tag)                                          \
  if (unlikely((get_imm_tag(val)) != (tag))) {                                 \
    MUSTTAIL return FAIL_SLOWPATH(ARGS);                                       \
  }
#define LOAD_TYPE_WITH_CHECK(name, type_s, val, tag)                           \
  TYPECHECK_TAG(val, PTR_TAG);                                                 \
  auto(name) = (type_s *)((val)-PTR_TAG);                                      \
  if (unlikely((name)->type != (tag))) {                                       \
    MUSTTAIL return FAIL_SLOWPATH(ARGS);                                       \
  }

LIBRARY_FUNC(ILOOP) {}
END_LIBRARY_FUNC
LIBRARY_FUNC(LOOP) {
  if (unlikely((hotmap[hotmap_hash(pc)]) <= hotmap_loop)) {
    MUSTTAIL return RECORD_START(ARGS);
  }
  hotmap[hotmap_hash(pc)] -= hotmap_loop;
}
END_LIBRARY_FUNC

LIBRARY_FUNC(IFUNC) {
  if (argcnt != ra) {
    MUSTTAIL return FAIL_SLOWPATH_ARGCNT(ARGS);
  }
  afl_trace(pc);
}
END_LIBRARY_FUNC

LIBRARY_FUNC(FUNC) {
  if (argcnt != ra) {
    MUSTTAIL return FAIL_SLOWPATH_ARGCNT(ARGS);
  }
  if (unlikely((hotmap[hotmap_hash(pc)] -= hotmap_rec) == 0)) {
    MUSTTAIL return RECORD_START(ARGS);
  }

  afl_trace(pc);
}
END_LIBRARY_FUNC

LIBRARY_FUNC(IFUNCV) {
  if (argcnt < ra) {
    MUSTTAIL return FAIL_SLOWPATH_ARGCNT(ARGS);
  }
  stack_top = &frame[ra + argcnt];
  frame[ra] = build_list(ra, argcnt - ra, frame);
  afl_trace(pc);
}
END_LIBRARY_FUNC

LIBRARY_FUNC(FUNCV) {
  if (argcnt < ra) {
    MUSTTAIL return FAIL_SLOWPATH_ARGCNT(ARGS);
  }
  if (unlikely((hotmap[hotmap_hash(pc)] -= hotmap_rec) == 0)) {
    MUSTTAIL return RECORD_START(ARGS);
  }
  stack_top = &frame[ra + argcnt];
  frame[ra] = build_list(ra, argcnt - ra, frame);
  afl_trace(pc);
}
END_LIBRARY_FUNC

LIBRARY_FUNC(ICLFUNC) {
  if (argcnt == ra) {
    pc += 2;
  } else {
    pc += INS_D(*(pc + 1)) + 1;
  }
  afl_trace(pc);
}
NEXT_FUNC

LIBRARY_FUNC(CLFUNC) {
  if (argcnt == ra) {
    if (unlikely((hotmap[hotmap_hash(pc)] -= hotmap_rec) == 0)) {
      MUSTTAIL return RECORD_START(ARGS);
    }
    pc += 2;
  } else {
    pc += INS_D(*(pc + 1)) + 1;
  }
  afl_trace(pc);
}
NEXT_FUNC

LIBRARY_FUNC(ICLFUNCV) {
  if (argcnt < ra) {
    pc += INS_D(*(pc + 1)) + 1;
  } else {
    stack_top = &frame[ra + argcnt];
    frame[ra] = build_list(ra, argcnt - ra, frame);
    pc += 2;
  }

  afl_trace(pc);
}
NEXT_FUNC

LIBRARY_FUNC(CLFUNCV) {
  if (argcnt < ra) {
    pc += INS_D(*(pc + 1)) + 1;
  } else {
    if (unlikely((hotmap[hotmap_hash(pc)] -= hotmap_rec) == 0)) {
      MUSTTAIL return RECORD_START(ARGS);
    }
    stack_top = &frame[ra + argcnt];
    frame[ra] = build_list(ra, argcnt - ra, frame);
    pc += 2;
  }

  afl_trace(pc);
}
NEXT_FUNC

LIBRARY_FUNC_D(KSHORT) {
  // RD could be negative, do shift anyway.
  // Should be already checked in frontend.
  //
  // Extends sign to 64 bits, then ignores sign for shift,
  // then casts back to signed.
  frame[ra] = tag_fixnum(rd);
}
END_LIBRARY_FUNC

LIBRARY_FUNC_D(JMP) { pc += rd; }
NEXT_FUNC

LIBRARY_FUNC(IRET1) {
  pc = (unsigned int *)frame[-1];
  frame[-1] = frame[ra];
  frame -= (INS_A(*(pc - 1)) + 1);
}
NEXT_FUNC

LIBRARY_FUNC(RET1) {
  pc = (unsigned int *)frame[-1];
  frame[-1] = frame[ra];
  frame -= (INS_A(*(pc - 1)) + 1);
}
NEXT_FUNC

#define END_FUNC }
LIBRARY_FUNC(HALT) {} //!OCLINT unused parameter
END_FUNC

// Note signed-ness of rc.
#define LIBRARY_FUNC_MATH_VN(name, op)                                         \
  LIBRARY_FUNC_B(name)                                                         \
  char rc = (instr >> 8) & 0xff;                                               \
  long fb = frame[rb];                                                         \
  TYPECHECK_TAG(fb, FIXNUM_TAG);                                               \
  if (unlikely(__builtin_##op##_overflow(fb, tag_fixnum(rc), &frame[ra]))) {   \
    MUSTTAIL return FAIL_SLOWPATH(ARGS);                                       \
  }                                                                            \
  END_LIBRARY_FUNC

LIBRARY_FUNC_MATH_VN(SUBVN, sub);
LIBRARY_FUNC_MATH_VN(ADDVN, add);

// Note overflow may smash dest, so don't use frame[ra] directly.
#define OVERFLOW_OP(op, name, shift)                                           \
  long tmp;                                                                    \
  if (unlikely(__builtin_##op##_overflow(fb, fc >> (shift), &tmp))) {          \
    MUSTTAIL return INS_##name##_SLOWPATH(ARGS);                               \
  }                                                                            \
  frame[ra] = tmp;

// Shift is necessary for adjusting the tag for mul.
#define LIBRARY_FUNC_MATH_VV(name, op2, overflow)                              \
  NOINLINE void NO_LINT INS_##name##_SLOWPATH(PARAMS) {                        \
    DEBUG_VM(#name);                                                           \
    unsigned char rb = instr & 0xff;                                           \
    unsigned char rc = (instr >> 8) & 0xff;                                    \
                                                                               \
    auto fb = frame[rb];                                                       \
    auto fc = frame[rc];                                                       \
    double x_b;                                                                \
    double x_c;                                                                \
    if (is_flonum(fb)) {                                                       \
      x_b = to_flonum(fb)->x;                                                  \
    } else if (is_fixnum(fb)) {                                                \
      x_b = to_fixnum(fb);                                                     \
    } else {                                                                   \
      MUSTTAIL return FAIL_SLOWPATH(ARGS);                                     \
    }                                                                          \
    if (is_flonum(fc)) {                                                       \
      x_c = to_flonum(fc)->x;                                                  \
    } else if (is_fixnum(fc)) {                                                \
      x_c = to_fixnum(fc);                                                     \
    } else {                                                                   \
      MUSTTAIL return FAIL_SLOWPATH(ARGS);                                     \
    }                                                                          \
                                                                               \
    stack_top = &frame[ra + 1];                                                \
    flonum_s *r = GC_malloc(sizeof(flonum_s));                                 \
    *r = (flonum_s){FLONUM_TAG, 0, op2(x_b, x_c)};                             \
    frame[ra] = tag_flonum(r);                                                 \
    pc++;                                                                      \
                                                                               \
    NEXT_INSTR;                                                                \
  }                                                                            \
                                                                               \
  LIBRARY_FUNC_BC_LOAD(name)                                                   \
  if (likely(is_fixnums(fb, fc))) {                                            \
    overflow;                                                                  \
  } else if (likely(get_tag(fb) == get_tag(fc)) && is_flonum(fc)) {            \
    auto x_b = to_flonum(fb)->x;                                               \
    auto x_c = to_flonum(fc)->x;                                               \
    stack_top = &frame[ra + 1];                                                \
    flonum_s *r = GC_malloc(sizeof(flonum_s));                                 \
    *r = (flonum_s){FLONUM_TAG, 0, op2(x_b, x_c)};                             \
    frame[ra] = tag_flonum(r);                                                 \
  } else {                                                                     \
    MUSTTAIL return INS_##name##_SLOWPATH(ARGS);                               \
  }                                                                            \
  END_LIBRARY_FUNC

#define LIBRARY_FUNC_MATH_OVERFLOW_VV(name, op, op2, shift)                    \
  LIBRARY_FUNC_MATH_VV(name, op2, OVERFLOW_OP(op, name, shift));

#define MATH_ADD(a, b) ((a) + (b))
#define MATH_SUB(a, b) ((a) - (b))
#define MATH_MUL(a, b) ((a) * (b))
#define MATH_DIV(a, b) ((a) / (b))

LIBRARY_FUNC_MATH_OVERFLOW_VV(ADDVV, add, MATH_ADD, 0);
LIBRARY_FUNC_MATH_OVERFLOW_VV(SUBVV, sub, MATH_SUB, 0);
LIBRARY_FUNC_MATH_OVERFLOW_VV(MULVV, mul, MATH_MUL, 3);
LIBRARY_FUNC_MATH_VV(DIV, MATH_DIV, frame[ra] = ((uint64_t)(fb / fc) << 3));
LIBRARY_FUNC_MATH_VV(REM, remainder,
                     frame[ra] = ((uint64_t)((fb >> 3) % (fc >> 3))) << 3);

#define LIBRARY_FUNC_EQ(name, iftrue, iffalse, finish)                         \
  LIBRARY_FUNC_BC_LOAD(name)                                                   \
  if (fb == fc) {                                                              \
    iftrue;                                                                    \
  } else {                                                                     \
    iffalse;                                                                   \
  }                                                                            \
                                                                               \
  pc += (finish);                                                              \
  afl_trace(pc);                                                               \
  NEXT_INSTR;                                                                  \
  }

LIBRARY_FUNC_EQ(EQ, frame[ra] = TRUE_REP, frame[ra] = FALSE_REP, 1);
LIBRARY_FUNC_EQ(JEQ, pc += 2, pc += INS_D(*(pc + 1)) + 1, 0);
LIBRARY_FUNC_EQ(JNEQ, pc += INS_D(*(pc + 1)) + 1, pc += 2, 0);

gc_obj vm_memq(gc_obj fb, gc_obj fc) {
  auto cur = fc;
  while (is_cons(cur)) {
    cons_s *cell = to_cons(cur);
    if (fb == cell->a) {
      return cur;
    }
    cur = cell->b;
  }
  return FALSE_REP;
}

LIBRARY_FUNC_BC_LOAD(MEMQ) { frame[ra] = vm_memq(fb, fc); }
END_LIBRARY_FUNC

long vm_assv(long fb, long fc) {
  auto cur = fc;
  while (is_cons(cur)) {
    cons_s *cell = to_cons(cur);
    if (!is_cons(cell->a)) {
      // TODO(djwatson) error propagates through jit
      printf("Invalid assoc list in jit\n");
      exit(-1);
    }
    cons_s *cella = to_cons(cell->a);
    if (fb == cella->a) {
      return cell->a;
    }
    if (is_flonum(fb) && is_flonum(cella->a) &&
        to_flonum(fb)->x == to_flonum(cella->a)->x) {
      return cell->a;
    }

    cur = cell->b;
  }
  return FALSE_REP;
}

LIBRARY_FUNC_BC_LOAD(ASSV) { frame[ra] = vm_assv(fb, fc); }
END_LIBRARY_FUNC

long vm_assq(long fb, long fc) {
  auto cur = fc;
  while (is_cons(cur)) {
    cons_s *cell = to_cons(cur);
    if (!is_cons(cell->a)) {
      // TODO(djwatson) error propagates through jit
      printf("Invalid assoc list in jit\n");
      exit(-1);
    }
    cons_s *cella = to_cons(cell->a);
    if (fb == cella->a) {
      return cell->a;
    }
    cur = cell->b;
  }
  return FALSE_REP;
}

LIBRARY_FUNC_BC_LOAD(ASSQ) { frame[ra] = vm_assq(fb, fc); }
END_LIBRARY_FUNC

gc_obj vm_length(gc_obj fb) {
  int64_t cnt = 0;
  auto cur = fb;
  while (true) {
    if (!is_cons(cur)) {
      break;
    }
    cnt++;
    cur = to_cons(cur)->b;
  }
  return tag_fixnum(cnt);
}

LIBRARY_FUNC_B_LOAD(LENGTH) { frame[ra] = vm_length(fb); }
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME("EQUAL?", EQUAL) { frame[ra] = equalp(fb, fc); }
END_LIBRARY_FUNC

#define LIBRARY_FUNC_NUM_CMP(name, op, func)                                   \
  LIBRARY_FUNC_BC_LOAD(name##_SLOWPATH)                                        \
  double x_b;                                                                  \
  double x_c;                                                                  \
  if (is_flonum(fb)) {                                                         \
    x_b = to_flonum(fb)->x;                                                    \
  } else if (is_fixnum(fb)) {                                                  \
    x_b = to_fixnum(fb);                                                       \
  } else {                                                                     \
    MUSTTAIL return FAIL_SLOWPATH(ARGS);                                       \
  }                                                                            \
  if (is_flonum(fc)) {                                                         \
    x_c = to_flonum(fc)->x;                                                    \
  } else if (is_fixnum(fc)) {                                                  \
    x_c = to_fixnum(fc);                                                       \
  } else {                                                                     \
    MUSTTAIL return FAIL_SLOWPATH(ARGS);                                       \
  }                                                                            \
                                                                               \
  func(x_b, x_c, op);                                                          \
                                                                               \
  NEXT_INSTR;                                                                  \
  }                                                                            \
  LIBRARY_FUNC_BC_LOAD(name)                                                   \
  if (likely(is_fixnums(fb, fc))) {                                            \
    func(fb, fc, op);                                                          \
  } else if (likely(get_tag(fb) == get_tag(fc)) && is_flonum(fc)) {            \
    auto x_b = to_flonum(fb)->x;                                               \
    auto x_c = to_flonum(fc)->x;                                               \
    func(x_b, x_c, op);                                                        \
  } else {                                                                     \
    MUSTTAIL return INS_##name##_SLOWPATH(ARGS);                               \
  }                                                                            \
                                                                               \
  NEXT_INSTR;                                                                  \
  }

#define MOVE_PC(a, b, op)                                                      \
  if (a op b) {                                                                \
    pc += 2;                                                                   \
  } else {                                                                     \
    pc += INS_D(*(pc + 1)) + 1;                                                \
  }                                                                            \
  afl_trace(pc);

#define SET_RES(a, b, op)                                                      \
  if (a op b) {                                                                \
    frame[ra] = TRUE_REP;                                                      \
  } else {                                                                     \
    frame[ra] = FALSE_REP;                                                     \
  }                                                                            \
  pc++;

LIBRARY_FUNC_NUM_CMP(JISLT, <, MOVE_PC);
LIBRARY_FUNC_NUM_CMP(JISEQ, ==, MOVE_PC);
LIBRARY_FUNC_NUM_CMP(JISNEQ, !=, MOVE_PC); //!OCLINT
LIBRARY_FUNC_NUM_CMP(JISLTE, <=, MOVE_PC);
LIBRARY_FUNC_NUM_CMP(JISGT, >, MOVE_PC);
LIBRARY_FUNC_NUM_CMP(JISGTE, >=, MOVE_PC);
LIBRARY_FUNC_NUM_CMP(ISLT, <, SET_RES);
LIBRARY_FUNC_NUM_CMP(ISGT, >, SET_RES);
LIBRARY_FUNC_NUM_CMP(ISLTE, <=, SET_RES);
LIBRARY_FUNC_NUM_CMP(ISGTE, >=, SET_RES);
LIBRARY_FUNC_NUM_CMP(ISEQ, ==, SET_RES);

#define LIBRARY_FUNC_JISF(name, iftrue, iffalse)                               \
  LIBRARY_FUNC_B_LOAD(name)                                                    \
  if (fb == FALSE_REP) {                                                       \
    pc += (iftrue);                                                            \
  } else {                                                                     \
    pc += (iffalse);                                                           \
  }                                                                            \
                                                                               \
  NEXT_INSTR;                                                                  \
  }
LIBRARY_FUNC_JISF(JISF, INS_D(*(pc + 1)) + 1, 2);
LIBRARY_FUNC_JISF(JIST, 2, INS_D(*(pc + 1)) + 1);

LIBRARY_FUNC_D(GGET) {
  symbol *gp = (symbol *)(const_table[rd] - SYMBOL_TAG);
  if (unlikely(gp->val == UNDEFINED_TAG)) {
    MUSTTAIL return UNDEFINED_SYMBOL_SLOWPATH(ARGS);
  }

  frame[ra] = gp->val;
}
END_LIBRARY_FUNC

LIBRARY_FUNC_D(GSET) {
  symbol *gp = (symbol *)(const_table[rd] - SYMBOL_TAG);
#ifdef JIT
  if (gp->opt != 0 && gp->opt != -1) {
    if (gp->val != UNDEFINED_TAG) {
      // printf("Gupgrade %s\n", ((string_s*)(gp->name-PTR_TAG))->str);
      for (uint32_t i = 0; i < hmlen(gp->lst); i++) {
        // printf("Get trace %i\n", gp->lst[i].key);
        trace_flush(trace_cache_get(gp->lst[i].key), true);
      }
      hmfree(gp->lst);
      gp->opt = -1;
    }
  }
#endif
  GC_log_obj(gp);
  gp->val = frame[ra];
}
END_LIBRARY_FUNC

LIBRARY_FUNC_D(KFUNC) { frame[ra] = (long)funcs[rd]; }
END_LIBRARY_FUNC

LIBRARY_FUNC_D(KONST) { frame[ra] = const_table[rd]; }
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(MOV) { frame[ra] = fb; }
END_LIBRARY_FUNC

LIBRARY_FUNC_B(BOX) {
  stack_top = &frame[(rb > ra ? rb : ra) + 1];
  auto box = (cons_s *)GC_malloc(sizeof(cons_s));

  box->type = CONS_TAG;
  box->rc = 0;
  box->a = frame[rb];
  box->b = NIL_TAG;
  frame[ra] = (long)box | CONS_TAG;
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(UNBOX) {
  auto box = (cons_s *)(fb - CONS_TAG);
  frame[ra] = box->a;
}
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME("SET-BOX!", SET_BOX) {
  auto box = (cons_s *)(fb - CONS_TAG);
  GC_log_obj(box);
  box->a = fc;
}
END_LIBRARY_FUNC

#define LIBRARY_FUNC_GUARD(name, iftrue, iffalse, finish)                      \
  LIBRARY_FUNC_BC(name)                                                        \
  long fb = frame[rb];                                                         \
                                                                               \
  if ((is_literal(rc) && (rc == get_imm_tag(fb))) ||                           \
      (is_ptr(fb) && (get_ptr_tag(fb) == rc)) ||                               \
      (!is_literal(rc) && get_tag(fb) == rc)) {                                \
    iftrue;                                                                    \
  } else {                                                                     \
    iffalse;                                                                   \
  }                                                                            \
                                                                               \
  pc += (finish);                                                              \
  afl_trace(pc);                                                               \
  NEXT_INSTR;                                                                  \
  }

LIBRARY_FUNC_GUARD(GUARD, frame[ra] = TRUE_REP, frame[ra] = FALSE_REP, 1);
LIBRARY_FUNC_GUARD(JGUARD, pc += 2, pc += INS_D(*(pc + 1)) + 1, 0);
LIBRARY_FUNC_GUARD(JNGUARD, pc += INS_D(*(pc + 1)) + 1, pc += 2, 0);

LIBRARY_FUNC_B(VECTOR) {
  stack_top = &frame[ra + rb];
  auto closure = (closure_s *)GC_malloc(sizeof(long) * (rb + 2));
  closure->type = VECTOR_TAG;
  closure->rc = 0;
  closure->len = rb << 3;
  for (int i = 0; i < rb; i++) {
    closure->v[i] = frame[ra + i];
  }
  frame[ra] = (long)closure | VECTOR_TAG;
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B(CLOSURE) {
  // free vars + type + len + function ptr
  stack_top = &frame[ra + rb];
  auto closure = (closure_s *)GC_malloc(sizeof(long) * (rb + 2));
  closure->type = CLOSURE_TAG;
  closure->rc = 0;
  closure->len = rb << 3;

  for (int i = 0; i < rb; i++) {
    closure->v[i] = frame[ra + i];
  }
  // Record polymorphic
  auto fun = (bcfunc *)frame[ra];
  if (fun->poly_cnt < 50) {
    fun->poly_cnt++;
    /* if (fun->poly_cnt == 50) { */
    /*   printf("Polymorphic func: %s\n", fun->name); */
    /* } */
  }
  frame[ra] = (long)closure | CLOSURE_TAG;
}
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_NAME("CLOSURE-GET", CLOSURE_GET) {
  auto fb = frame[rb];
  // TYPECHECK_TAG(fb, CLOSURE_TAG);
  auto closure = (closure_s *)(fb - CLOSURE_TAG);
  frame[ra] = closure->v[1 + rc];
}
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_NAME("CLOSURE-SET", CLOSURE_SET) {
  auto fa = frame[ra];
  // No need to typecheck, that would be bad bytecode.
  auto closure = (closure_s *)(fa - CLOSURE_TAG);
  GC_log_obj(closure);
  closure->v[1 + rc] = frame[rb];
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME("CLOSURE-PTR", CLOSURE_PTR) {
  TYPECHECK_TAG(fb, CLOSURE_TAG);
  auto closure = (closure_s *)(fb - CLOSURE_TAG);
  frame[ra] = closure->v[0];
}
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD(APPLY) {
  if (unlikely(!is_closure(fb))) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  // TODO check type NIL

  long a = 0;
  for (; (fc & TAG_MASK) == CONS_TAG; a++) {
    auto cons = (cons_s *)(fc - CONS_TAG);
    frame[a + 1] = cons->a;
    fc = cons->b;
  }
  frame[0] = fb;
  auto clo = (closure_s *)(fb - CLOSURE_TAG);
  auto func = (bcfunc *)clo->v[0];
  pc = &func->code[0];
  argcnt = a + 1;
}
NEXT_FUNC

#ifdef PROFILER
bool in_jit = false;
#endif

LIBRARY_FUNC_D(JFUNC) {
  // auto tnum = instr;
  //  printf("JFUNC/JLOOP run %i\n", rd);
  //  printf("frame before %i %li %li \n", frame-stack, frame[0], frame[1]);
  (void)rd;
#if defined(JIT)
  auto trace = trace_cache_get(rd);
  if (INS_OP(trace->startpc) == CLFUNC || INS_OP(trace->startpc) == ICLFUNC) {
    if (argcnt != INS_A(trace->startpc)) {
      pc += INS_D(*(pc + 1)) + 1;
      NEXT_INSTR;
    }
  }
  if (INS_OP(trace->startpc) == CLFUNCV || INS_OP(trace->startpc) == ICLFUNCV) {
    if (argcnt < INS_A(trace->startpc)) {
      pc += INS_D(*(pc + 1)) + 1;
      NEXT_INSTR;
    }
  }
  // Check for argument type match
  bool match = false;
  while (trace) {
    match = true;
    for (uint64_t i = 0; i < arrlen(trace->ops); i++) {
      auto op = &trace->ops[i];
      if (op->op != IR_ARG) {
        break;
      }
      uint8_t typ = get_object_ir_type(frame[op->op1]);
      if ((typ & ~IR_INS_TYPE_GUARD) != (op->type & ~IR_INS_TYPE_GUARD)) {
        match = false;
        break;
      }
    }
    if (match) {
      break;
    }
    trace = trace->next;
  }
  if (!match) {
    instr = trace_cache_get(rd)->startpc;
    unsigned char op = instr & 0xff;
    ra = (instr >> 8) & 0xff;
    instr >>= 16;
    op_func *op_table_arg_c = (op_func *)op_table_arg;
    MUSTTAIL return op_table_arg_c[op](ARGS);
  }
  assert(trace);
  // Build vararg list if required
  if (INS_OP(trace->startpc) == FUNCV) {
    stack_top = &frame[ra + argcnt];
    frame[ra] = build_list(ra, argcnt - ra, frame);
  }
  if (INS_OP(trace->startpc) == CLFUNCV) {
    stack_top = &frame[ra + argcnt];
    frame[ra] = build_list(ra, argcnt - ra, frame);
  }
#ifdef PROFILER
  in_jit = true;
#endif
  int res;
  afl_trace(pc);
  {
    // Convince GCC that jit_run won't save the address of any of its
    // arguments, so GCC will correctly make NEXT_INSTR a tailcall.
    auto pc2 = pc;
    auto frame2 = frame;
    auto argcnt2 = argcnt;
    res = jit_run(trace, &pc2, &frame2, &argcnt2);
    pc = pc2;
    frame = frame2;
    argcnt = argcnt2;
  }
  afl_trace(pc);
#ifdef PROFILER
  in_jit = false;
#endif
#else
  auto res = 0;
#endif

  frame_top = stack + stacksz - 256;
  // printf("frame after %i %li %li \n", frame-stack, frame[0], frame[1]);
  if (unlikely(res)) {
    // Turn on recording again
    op_table_arg = (void **)l_op_table_record;
  }
}
NEXT_FUNC

#define LIBRARY_FUNC_COPY(name, copied)
LIBRARY_FUNC_COPY(JLOOP, JFUNC);
#define INS_JLOOP INS_JFUNC

LIBRARY_FUNC_B(CALL) {
  auto cl = frame[ra + 1];
  TYPECHECK_TAG(cl, CLOSURE_TAG);
  auto closure = (closure_s *)(cl - CLOSURE_TAG);

  bcfunc *func = (bcfunc *)closure->v[0];
  auto old_pc = pc;
  pc = &func->code[0];
  frame[ra] = (long)(old_pc + 1);
  frame += ra + 1;
  argcnt = rb - 1;
  if (unlikely((frame + 256) > frame_top)) {
    MUSTTAIL return EXPAND_STACK_SLOWPATH(ARGS);
  }
}
NEXT_FUNC

LIBRARY_FUNC_B(LCALL) {
  auto func = (bcfunc *)frame[ra];

  auto old_pc = pc;
  pc = &func->code[0];
  frame[ra] = (long)(old_pc + 1);
  frame += ra + 1;
  argcnt = rb - 1;
  if (unlikely((frame + 256) > frame_top)) {
    MUSTTAIL return EXPAND_STACK_SLOWPATH(ARGS);
  }
}
NEXT_FUNC

LIBRARY_FUNC_B(CALLT) {
  auto cl = frame[ra + 1];
  TYPECHECK_TAG(cl, CLOSURE_TAG);
  auto closure = (closure_s *)(cl - CLOSURE_TAG);

  bcfunc *func = (bcfunc *)closure->v[0];
  pc = &func->code[0];

  long start = ra + 1;
  argcnt = rb - 1;
  for (auto i = 0; i < argcnt; i++) {
    frame[i] = frame[start + i];
  }
  // No need to stack size check for tailcalls since we reuse the frame.
}
NEXT_FUNC

LIBRARY_FUNC_B(LCALLT) {
  auto func = (bcfunc *)frame[ra];
  pc = &func->code[0];

  long start = ra + 1;
  argcnt = rb - 1;
  for (auto i = 0; i < argcnt; i++) {
    frame[i] = frame[start + i];
  }
  // No need to stack size check for tailcalls since we reuse the frame.
}
NEXT_FUNC

#define LIBRARY_FUNC_EQV(name, name2, iftrue, iffalse, finish)                 \
  LIBRARY_FUNC_BC_LOAD_NAME(name, name2)                                       \
  if (fb == fc) {                                                              \
    iftrue;                                                                    \
  } else if (get_tag(fb) == get_tag(fc) && is_flonum(fc)) {                    \
    auto x_b = to_flonum(fb)->x;                                               \
    auto x_c = to_flonum(fc)->x;                                               \
    if (x_b == x_c) {                                                          \
      iftrue;                                                                  \
    } else {                                                                   \
      iffalse;                                                                 \
    }                                                                          \
  } else {                                                                     \
    iffalse;                                                                   \
  }                                                                            \
                                                                               \
  pc += (finish);                                                              \
  afl_trace(pc);                                                               \
  NEXT_INSTR;                                                                  \
  }

LIBRARY_FUNC_EQV(EQV?, EQV, frame[ra] = TRUE_REP, frame[ra] = FALSE_REP, 1);
LIBRARY_FUNC_EQV(JEQV, JEQV, pc += 2, pc += INS_D(*(pc + 1)) + 1, 0);
LIBRARY_FUNC_EQV(JNEQV, JNEQV, pc += INS_D(*(pc + 1)) + 1, pc += 2, 0);

static uint32_t max3(uint32_t a, uint32_t b, uint32_t c) {
  if (a > b) {
    if (a > c) {
      return a;
    }
    return c;
  }
  if (b > c) {
    return b;
  }
  return c;
}

LIBRARY_FUNC_BC(CONS) {
  stack_top = &frame[max3(ra, rb, rc) + 1];
  auto c = (cons_s *)GC_malloc(sizeof(cons_s));

  c->type = CONS_TAG;
  c->rc = 0;
  c->a = frame[rb];
  c->b = frame[rc];

  frame[ra] = (long)c | CONS_TAG;
}
END_LIBRARY_FUNC

#define LIBRARY_FUNC_CONS_OP(name, field)                                      \
  LIBRARY_FUNC_B_LOAD(name)                                                    \
  TYPECHECK_TAG(fb, CONS_TAG);                                                 \
  auto c = (cons_s *)(fb - CONS_TAG);                                          \
  frame[ra] = c->field;                                                        \
  END_LIBRARY_FUNC

LIBRARY_FUNC_CONS_OP(CAR, a);
LIBRARY_FUNC_CONS_OP(CDR, b);

void vm_make_vector(long vec, long val) {
  vector_s *v = (vector_s *)(vec & ~TAG_MASK);

  long len = v->len >> 3;
  long *p = &v->v[0];
  long *end = &v->v[len];
  for (; p < end; p++) {
    *p = val;
  }
}

LIBRARY_FUNC_BC_NAME("MAKE-VECTOR", MAKE_VECTOR) {
  long fb = frame[rb];
  TYPECHECK_FIXNUM(fb);

  auto len = fb >> 3;
  if (len < 0) {
    MUSTTAIL return FAIL_SLOWPATH_ARGCNT(ARGS);
  }
  stack_top = &frame[max3(ra, rb, rc) + 1];
  auto vec = (vector_s *)GC_malloc(sizeof(long) * (len + 2));
  // Load frame[rc] *after* GC
  long fc = frame[rc];
  vec->type = VECTOR_TAG;
  vec->rc = 0;
  vec->len = fb;
  for (long i = 0; i < len; i++) {
    vec->v[i] = fc;
  }

  frame[ra] = (long)vec | VECTOR_TAG;
}
END_LIBRARY_FUNC

void vm_make_string(gc_obj str, gc_obj ch) {
  // TODO(djwatson) check if we can use to_string from jit
  string_s *s = to_raw_ptr(str);
  auto c = to_char(ch);

  auto len = to_fixnum(s->len);
  memset(&s->str[0], c, len);
  s->str[len] = '\0';
}

// TODO could be BC_LOAD_NAME?
LIBRARY_FUNC_BC_NAME("MAKE-STRING", MAKE_STRING) {
  long fb = frame[rb];
  TYPECHECK_FIXNUM(fb);
  auto len = fb >> 3;
  if (len < 0) {
    MUSTTAIL return FAIL_SLOWPATH_ARGCNT(ARGS);
  }
  stack_top = &frame[max3(ra, rb, rc) + 1];
  auto str = (string_s *)GC_malloc((sizeof(long) * 2) + len + 1);

  long fc = frame[rc]; // Load fc after GC
  TYPECHECK_IMMEDIATE(fc, CHAR_TAG);

  str->type = STRING_TAG;
  str->rc = 0;
  str->len = fb;
  for (long i = 0; i < len; i++) {
    str->str[i] = (char)((fc >> 8) & 0xff);
  }
  str->str[len] = '\0';

  frame[ra] = (long)str | PTR_TAG;
}
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME("VECTOR-REF", VECTOR_REF) {
  TYPECHECK_FIXNUM(fc);
  TYPECHECK_TAG(fb, VECTOR_TAG);
  auto vec = (vector_s *)(fb - VECTOR_TAG);
  long pos = fc >> 3;
  if ((long)(vec->len >> 3) - pos < 0) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = vec->v[pos];
}
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME("STRING-REF", STRING_REF) {
  TYPECHECK_FIXNUM(fc);
  LOAD_TYPE_WITH_CHECK(str, string_s, fb, STRING_TAG);
  long pos = fc >> 3;
  if ((long)(str->len >> 3) - pos < 0) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  frame[ra] = tag_char(str->str[pos]);
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME("VECTOR-LENGTH", VECTOR_LENGTH) {
  TYPECHECK_TAG(fb, VECTOR_TAG);
  auto vec = to_vector(fb);
  frame[ra] = (long)(vec->len);
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME("STRING-LENGTH", STRING_LENGTH) {
  LOAD_TYPE_WITH_CHECK(str, string_s, fb, STRING_TAG);
  frame[ra] = (long)(str->len);
}
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME("VECTOR-SET!", VECTOR_SET) {
  auto fa = frame[ra];
  TYPECHECK_FIXNUM(fb);
  TYPECHECK_TAG(fa, VECTOR_TAG);
  auto vec = (vector_s *)(fa - VECTOR_TAG);
  long pos = fb >> 3;
  if ((long)(vec->len >> 3) - pos <= 0) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  GC_log_obj(vec);

  vec->v[pos] = fc;
}
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME("STRING-SET!", STRING_SET) {
  auto fa = frame[ra];
  TYPECHECK_FIXNUM(fb);
  TYPECHECK_IMMEDIATE(fc, CHAR_TAG);
  LOAD_TYPE_WITH_CHECK(str, string_s, fa, STRING_TAG);
  long pos = fb >> 3;
  if ((long)(str->len >> 3) - pos <= 0) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  str->str[pos] = (char)((fc >> 8) & 0xff);
}
END_LIBRARY_FUNC

#define LIBRARY_FUNC_CONS_SET_OP(str, name, field)                             \
  LIBRARY_FUNC_B_LOAD_NAME(str, name)                                          \
  auto fa = frame[ra];                                                         \
  TYPECHECK_TAG(fa, CONS_TAG);                                                 \
  auto cons = (cons_s *)(fa - CONS_TAG);                                       \
  GC_log_obj(cons);                                                            \
  cons->field = fb;                                                            \
  END_LIBRARY_FUNC

LIBRARY_FUNC_CONS_SET_OP("SET-CAR!", SET_CAR, a);
LIBRARY_FUNC_CONS_SET_OP("SET-CDR!", SET_CDR, b);

// Called from jit. TODO could inline in jit.
void vm_write(long obj, long port_obj) {
  auto port = (port_s *)(port_obj - PTR_TAG);
  print_obj(obj, port->file);
}

LIBRARY_FUNC_BC_LOAD(WRITE) {
  LOAD_TYPE_WITH_CHECK(port, port_s, fc, PORT_TAG);
  print_obj(fb, port->file);
}
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME("WRITE-U8", WRITE_U8) {
  LOAD_TYPE_WITH_CHECK(port, port_s, fc, PORT_TAG);
  TYPECHECK_FIXNUM(fb);
  long byte = fb >> 3;
  unsigned char b = byte;
  if (unlikely(byte >= 256)) {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }

  fputc(b, port->file);
}
END_LIBRARY_FUNC

LIBRARY_FUNC_BC_LOAD_NAME("WRITE-DOUBLE", WRITE_DOUBLE) {
  LOAD_TYPE_WITH_CHECK(port, port_s, fc, PORT_TAG);
  TYPECHECK_TAG(fb, FLONUM_TAG);
  auto flo = (flonum_s *)(fb - FLONUM_TAG);

  fwrite(&flo->x, sizeof(flo->x), 1, port->file);
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME("SYMBOL->STRING", SYMBOL_STRING) {
  TYPECHECK_TAG(fb, SYMBOL_TAG);
  auto sym = (symbol *)(fb - SYMBOL_TAG);
  frame[ra] = sym->name;
}
END_LIBRARY_FUNC

long vm_string_symbol(gc_obj in) {
  // TODO jit still as the ptr tag.
  auto str = to_string(in);

  auto res = symbol_table_find(str);
  if (res) {
    return tag_symbol(res);
  }
  auto inserted = symbol_table_insert(str, false);
  if (!inserted) {
    return FALSE_REP;
  }
  return inserted;
}

LIBRARY_FUNC_B_LOAD_NAME("STRING->SYMBOL", STRING_SYMBOL) {
  LOAD_TYPE_WITH_CHECK(str, string_s, fb, STRING_TAG);
  auto res = symbol_table_find(str);
  if (res) {
    frame[ra] = tag_symbol(res);
  } else {
    frame[ra] = symbol_table_insert(str, true);
  }
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME("CHAR->INTEGER", CHAR_INTEGER) {
  TYPECHECK_IMMEDIATE(fb, CHAR_TAG);
  frame[ra] = fb >> 5;
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME("INTEGER->CHAR", INTEGER_CHAR) {
  TYPECHECK_FIXNUM(fb);
  frame[ra] = (fb << 5) + CHAR_TAG;
}
END_LIBRARY_FUNC

LIBRARY_FUNC_BC(OPEN) {
  auto fc = frame[rc];
  TYPECHECK_IMMEDIATE(fc, BOOL_TAG);

  stack_top = &frame[(ra > rb ? ra : rb) + 1];
  auto port = (port_s *)GC_malloc(sizeof(port_s));
  // Load FB (potentially a ptr) after GC
  auto fb = frame[rb];

  port->type = PORT_TAG;
  port->rc = 0;
  port->input_port = fc;
  port->eof = FALSE_REP;
  port->buf_sz = 0;
  port->buf_pos = 0;
  port->in_buffer = NULL;

  if (is_fixnum(fb)) {
    port->fd = frame[rb] >> 3;
  } else if (is_string(fb)) {
    auto str = to_string(fb);
    port->fd =
        open(str->str, fc == TRUE_REP ? O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC,
             0777);
    if (port->fd == -1) {
      printf("Could not open fd for file %s\n", str->str);
      exit(-1);
    }
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
  port->file = fdopen((int)port->fd, fc == TRUE_REP ? "r" : "w");
  if (port->file == NULL) {
    printf("FDopen fail\n");
    exit(-1);
  }
  port->in_buffer = malloc(IN_BUFFER_SZ);
  frame[ra] = tag_port(port);
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(CLOSE) {
  LOAD_TYPE_WITH_CHECK(port, port_s, fb, PORT_TAG);
  if (port->file) {
    fclose(port->file);
    port->file = NULL;
  }
  if (port->fd != -1) {
    close((int)port->fd);
    port->fd = -1;
  }
}
END_LIBRARY_FUNC

inline long vm_peek_char(gc_obj p) {
  // TODO jit still as the ptr tag.
  auto port = to_port(p);
  if (likely(port->buf_pos < port->buf_sz)) {
    return tag_char(port->in_buffer[port->buf_pos]);
  }
  port->buf_pos = 0;
  port->buf_sz = fread(port->in_buffer, 1, IN_BUFFER_SZ, port->file);
  if (port->buf_sz == 0) {
    port->eof = TRUE_REP;
    return EOF_TAG;
  }
  return tag_char(port->in_buffer[0]);
}

LIBRARY_FUNC_B_LOAD(PEEK) {
  LOAD_TYPE_WITH_CHECK(port, port_s, fb, PORT_TAG);
  frame[ra] = vm_peek_char(fb);
}
END_LIBRARY_FUNC

inline long vm_read_char(gc_obj p) {
  // TODO jit still as the ptr tag.
  auto port = to_port(p);
  if (likely(port->buf_pos < port->buf_sz)) {
    return tag_char(port->in_buffer[port->buf_pos++]);
  }
  port->buf_pos = 1;
  port->buf_sz = fread(port->in_buffer, 1, IN_BUFFER_SZ, port->file);
  if (port->buf_sz == 0) {
    port->eof = TRUE_REP;
    return EOF_TAG;
  }
  return tag_char(port->in_buffer[0]);
}

LIBRARY_FUNC_B_LOAD(READ) {
  LOAD_TYPE_WITH_CHECK(port, port_s, fb, PORT_TAG);
  frame[ra] = vm_read_char(fb);
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME("READ-LINE", READ_LINE) {
  LOAD_TYPE_WITH_CHECK(port, port_s, fb, PORT_TAG);
  // The extra block scope here is so that gcc's optimizer
  // will know it can release bufptr stack storage, otherwise
  // it can't know getline doesn't store it somewhere.
  // This prevents GCC -O2 from making this a tailcall.
  {
    size_t sz = 0;
    char *bufptr = NULL;
    ssize_t res = getline(&bufptr, &sz, port->file);
    if (res == -1) {
      port->eof = TRUE_REP;
      frame[ra] = EOF_TAG;
    } else {
      stack_top = &frame[ra + 1];
      auto str = (string_s *)GC_malloc(res + 16);
      str->type = STRING_TAG;
      str->rc = 0;
      str->len = res << 3;
      memcpy(str->str, bufptr, res);
      str->str[res - 1] = '\0';
      frame[ra] = (long)str + PTR_TAG;
    }
    free(bufptr);
  }
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(INEXACT) {
  if (is_fixnum(fb)) {
    stack_top = &frame[ra + 1];
    auto r = (flonum_s *)GC_malloc(sizeof(flonum_s));
    r->rc = 0;
    r->type = FLONUM_TAG;
    r->x = (double)to_fixnum(fb);
    frame[ra] = (long)r + FLONUM_TAG;
  } else if (is_flonum(fb)) {
    frame[ra] = fb;
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(EXACT) {
  if (is_fixnum(fb)) {
    frame[ra] = fb;
  } else if (is_flonum(fb)) {
    auto flo = to_flonum(fb);
    // TODO: check for bignum overflow.
    // TODO: left shift of negative number.
    frame[ra] = tag_fixnum((long)flo->x);
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD(ROUND) {
  if (is_fixnum(fb)) {
    frame[ra] = fb;
  } else if (is_flonum(fb)) {
    auto flo = to_flonum(fb);
    // auto res = roundeven(flo->x);
    auto res = flo->x - remainder(flo->x, 1.0);
    // auto res = round(flo->x);

    stack_top = &frame[ra + 1];
    auto r = (flonum_s *)GC_malloc(sizeof(flonum_s));
    r->rc = 0;
    r->type = FLONUM_TAG;
    r->x = res;
    frame[ra] = tag_flonum(r);
  } else {
    MUSTTAIL return FAIL_SLOWPATH(ARGS);
  }
}
END_LIBRARY_FUNC

#define LIBRARY_FUNC_FLONUM_MATH(name, func)                                   \
  LIBRARY_FUNC_B_LOAD(name)                                                    \
  if (is_flonum(fb)) {                                                         \
    auto flo = to_flonum(fb);                                                  \
    auto res = func(flo->x);                                                   \
                                                                               \
    stack_top = &frame[ra + 1];                                                \
    auto r = (flonum_s *)GC_malloc(sizeof(flonum_s));                          \
    r->rc = 0;                                                                 \
    r->type = FLONUM_TAG;                                                      \
    r->x = res;                                                                \
    frame[ra] = tag_flonum(r);                                                 \
  } else {                                                                     \
    MUSTTAIL return FAIL_SLOWPATH(ARGS);                                       \
  }                                                                            \
  END_LIBRARY_FUNC

LIBRARY_FUNC_FLONUM_MATH(SIN, sin);
LIBRARY_FUNC_FLONUM_MATH(SQRT, sqrt);
LIBRARY_FUNC_FLONUM_MATH(ATAN, atan);
LIBRARY_FUNC_FLONUM_MATH(COS, cos);
LIBRARY_FUNC_FLONUM_MATH(TRUNCATE, trunc);
LIBRARY_FUNC_FLONUM_MATH(FLOOR, floor);
LIBRARY_FUNC_FLONUM_MATH(CEILING, ceil);
LIBRARY_FUNC_FLONUM_MATH(EXP, exp);
LIBRARY_FUNC_FLONUM_MATH(LOG, log);
LIBRARY_FUNC_FLONUM_MATH(TAN, tan);
LIBRARY_FUNC_FLONUM_MATH(ASIN, asin);
LIBRARY_FUNC_FLONUM_MATH(ACOS, acos);

long vm_callcc(const gc_obj *frame) {
  auto sz = frame - stack;
  auto cont = (vector_s *)GC_malloc_no_collect(sz * sizeof(long) + 16);
  if (!cont) {
    return FALSE_REP;
  }
  cont->type = CONT_TAG;
  cont->rc = 0;
  cont->len = sz << 3;
  memcpy(cont->v, stack, sz * sizeof(long));

  return (long)cont | PTR_TAG;
}

LIBRARY_FUNC(CALLCC) {
  auto sz = frame - stack;

  stack_top = &frame[ra + 1];
  auto cont = (vector_s *)GC_malloc(sz * sizeof(long) + 16);
  cont->type = CONT_TAG;
  cont->rc = 0;
  cont->len = sz << 3;
  memcpy(cont->v, stack, sz * sizeof(long));

  frame[ra] = (long)cont | PTR_TAG;
}
END_LIBRARY_FUNC

long vm_cc_resume(long c) {
  closure_s *cont = (closure_s *)(c & ~TAG_MASK);
  memcpy(stack, cont->v, (cont->len >> 3) * sizeof(long));
  return (long)&stack[cont->len >> 3];
}

LIBRARY_FUNC_BC_LOAD_NAME("CALLCC-RESUME", CALLCC_RESUME) {
  LOAD_TYPE_WITH_CHECK(cont, vector_s, fb, CONT_TAG);
  memcpy(stack, cont->v, (cont->len >> 3) * sizeof(long));
  frame = &stack[cont->len >> 3];

  // DO A RET
  pc = (unsigned int *)frame[-1];
  frame[-1] = fc;
  frame -= (INS_A(*(pc - 1)) + 1);
}
NEXT_FUNC

LIBRARY_FUNC_B_LOAD_NAME("FILE-EXISTS?", FILE_EXISTS) {
  LOAD_TYPE_WITH_CHECK(str, string_s, fb, STRING_TAG)
  if (0 == access(str->str, F_OK)) {
    frame[ra] = TRUE_REP;
  } else {
    frame[ra] = FALSE_REP;
  }
}
END_LIBRARY_FUNC

LIBRARY_FUNC_B_LOAD_NAME("DELETE-FILE", DELETE_FILE) {
  LOAD_TYPE_WITH_CHECK(str, string_s, fb, STRING_TAG)
  if (0 == unlink(str->str)) {
    frame[ra] = TRUE_REP;
  } else {
    frame[ra] = FALSE_REP;
  }
}
END_LIBRARY_FUNC

///////////
#ifdef PROFILER
void INS_PROFILE_RET1_ADJ(PARAMS) {
  profile_pop_frame();
  profile_set_pc(pc);
  MUSTTAIL return INS_RET1(ARGS);
}

void INS_PROFILE_CALL_ADJ(PARAMS) {
  profile_add_frame(pc);
  profile_set_pc(pc);
  MUSTTAIL return INS_CALL(ARGS);
}

void INS_PROFILE_CALLCC_RESUME_ADJ(PARAMS) {
  // TODO make callcc resume work
  profile_pop_all_frames();
  profile_set_pc(pc);
  MUSTTAIL return INS_CALLCC_RESUME(ARGS);
}
#endif

////////////// Generate the instruction tables.

#ifdef PROFILER
#define X(name, str)                                                           \
  static void INS_PROFILE_##name(PARAMS) {                                     \
    profile_set_pc(pc);                                                        \
    MUSTTAIL return INS_##name(ARGS);                                          \
  }
BYTECODE_INSTRUCTIONS
#undef X
#endif

static void opcode_table_init() { //!OCLINT
#ifdef PROFILER
#define X(name, str) l_op_table_profile[name] = INS_PROFILE_##name;
  BYTECODE_INSTRUCTIONS
#undef X
#endif
#define X(name, str) l_op_table[name] = INS_##name;
  BYTECODE_INSTRUCTIONS
#undef X
}

// Main function runner.

EXPORT void run(bcfunc *func, long argcnt, const long *args) {
  vm_init();

  // Bytecode stub to get us to HALT.
  unsigned int final_code[] = {CODE(CALL, 0, 1, 0), CODE(HALT, 0, 0, 0)};
  unsigned int *code = &func->code[0];

  long *frame;
  // Initial stack setup has a return to bytecode stub above.

  stack[0] = (long)&final_code[1]; // return pc
  frame = &stack[1];
  frame_top = stack + stacksz - 256;

  for (long i = 0; i < argcnt; i++) {
    frame[i] = args[i];
  }

  unsigned int *pc = &code[0];

  for (int i = 0; i < hotmap_sz; i++) {
    hotmap[i] = hotmap_cnt;
  }

  opcode_table_init();
  // Setup instruction table.
  for (int i = 0; i < INS_MAX; i++) {
    l_op_table_record[i] = RECORD;
  }
#ifdef PROFILER
  if (profile) {
    l_op_table_profile[RET1] = INS_PROFILE_RET1_ADJ;
    l_op_table_profile[CALL] = INS_PROFILE_CALL_ADJ;
    l_op_table_profile[CALLCC_RESUME] = INS_PROFILE_CALLCC_RESUME_ADJ;
  }
#endif

  // Initial tailcalling-interpreter variable setup.
  unsigned int instr = *pc;
  unsigned char op = instr & 0xff;
  unsigned char ra = (instr >> 8) & 0xff;
  instr >>= 16;
  auto op_table_arg = (void **)l_op_table;
#ifdef PROFILER
  if (profile) {
    op_table_arg = (void **)l_op_table_profile;
    l_op_table_profile[op](ARGS);
  } else {
    l_op_table[op](ARGS);
  }
#else
  l_op_table[op](ARGS);
#endif

  stack_top = stack;

  // And after the call returns, we're done.  only HALT returns.
}
