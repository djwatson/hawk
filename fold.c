#include "fold.h"

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#include "array.h"
#include "gc.h"
#include "runtime.h"

typedef fold_result (*fold_func_type)(trace *t, ir_ins *in);

static fold_result fold_next(void) {
  return (fold_result){.action = FOLD_NEXT};
}
static fold_result fold_drop(void) {
  return (fold_result){.action = FOLD_DROP};
}
static fold_result fold_const(gc_obj constant) {
  return (fold_result){.action = FOLD_CONST, .constant = constant};
}
static fold_result fold_retry(void) {
  return (fold_result){.action = FOLD_RETRY};
}

static inline ir_ins_op swap_cmp_op(ir_ins_op op) {
  assert(op >= IR_LT && op <= IR_GTE);
  return (ir_ins_op)(op ^ 1);
}

static uint8_t fold_arg(trace *t, ir_ins *in, uint8_t idx) {
  auto arg_type = ir_ins_types[in->op];
  if (idx == 0 && (arg_type == IR_ARG_IR_NONE || arg_type == IR_ARG_IR_IR)) {
    return in->op1.constant ? FOLD_ARG_CONST : t->ins[in->op1.loc].op;
  }
  if (idx == 1 && arg_type == IR_ARG_IR_IR) {
    return in->op2.constant ? FOLD_ARG_CONST : t->ins[in->op2.loc].op;
  }
  return FOLD_ARG_ANY;
}

static uint32_t fold_key(trace *t, ir_ins *in) {
  uint32_t key = in->op << 16;
  key |= fold_arg(t, in, 0) << 8;
  key |= fold_arg(t, in, 1);
  return key;
}

#define IRFOLD(x)
#define IRFOLDX(x)
#define IRFOLDF(name)                                                          \
  static fold_result name(trace *t __attribute__((unused)),                    \
                          ir_ins *in __attribute__((unused)))
#define cur_ins (*in)

// If the inputs are always const, no need to guard anything!
IRFOLD(NE CONST CONST)
IRFOLD(EQ CONST CONST)
IRFOLD(GTE CONST CONST)
IRFOLD(LTE CONST CONST)
IRFOLD(GT CONST CONST)
IRFOLD(LT CONST CONST)
IRFOLDF(fold_guard_const_const) { return fold_drop(); }

IRFOLD(NE CONST _)
IRFOLD(ADD CONST _)
IRFOLD(EQ CONST _)
IRFOLD(MUL CONST _)
IRFOLDF(fold_commutative_const_lhs) {
  slot tmp = in->op1;
  in->op1 = in->op2;
  in->op2 = tmp;
  return fold_next();
}

IRFOLD(LT CONST _)
IRFOLD(GT CONST _)
IRFOLD(LTE CONST _)
IRFOLD(GTE CONST _)
IRFOLDF(fold_cmp_const_lhs) {
  slot tmp = in->op1;
  in->op1 = in->op2;
  in->op2 = tmp;
  in->op = swap_cmp_op(in->op);
  return fold_next();
}

IRFOLD(SUB CONST _)
IRFOLD(DIV CONST _)
IRFOLD(QUOTIENT CONST _)
IRFOLD(MOD CONST _)
IRFOLDF(fold_noncommutative_const_lhs) {
  // Materialize lhs constant to a register so emit can handle lhs as non-const.
  auto const_op = (ir_ins){
      .op = IR_CONST,
      .type = get_type_tag(t->consts[in->op1.loc]),
      .guard = false,
      .reg = REG_NONE,
      .spill = SPILL_NONE,
      .op1 = in->op1,
  };
  uint16_t idx = arrlen(t->ins);
  arrput(t->ins, const_op);
  in->op1 = (slot){.constant = false, .loc = idx};
  return fold_retry();
}

IRFOLD(NE _ CONST)
IRFOLDF(fold_guard_neq_any_const) {
  auto rhs = t->consts[in->op2.loc];
  bool rhs_bool = get_type_tag(rhs) == BOOL_TAG;
  bool lhs_flonum = false;
  if (in->op1.constant) {
    lhs_flonum = is_flonum(t->consts[in->op1.loc]);
  } else {
    lhs_flonum = t->ins[in->op1.loc].type == FLONUM_TAG;
  }
  if (rhs_bool && lhs_flonum) {
    return fold_drop();
  }
  return fold_next();
}

IRFOLD(INEXACT CONST _)
IRFOLDF(fold_inexact_const) {
  auto value = t->consts[in->op1.loc];
  return fold_const(numeric_inexact_value(value));
}

IRFOLD(EXACT CONST _)
IRFOLDF(fold_exact_const) {
  auto value = t->consts[in->op1.loc];
  return fold_const(numeric_exact_value(value));
}

IRFOLD(TRUNCATE CONST _)
IRFOLDF(fold_truncate_const) {
  auto value = t->consts[in->op1.loc];
  return fold_const(numeric_truncate_value(value));
}

IRFOLD(SUB CONST CONST)
IRFOLDF(fold_sub_const_const) {
  auto lhs = t->consts[in->op1.loc];
  auto rhs = t->consts[in->op2.loc];
  return fold_const(vm_runtime_math_sub_slow(lhs, rhs));
}

IRFOLD(ADD CONST CONST)
IRFOLDF(fold_add_const_const) {
  auto lhs = t->consts[in->op1.loc];
  auto rhs = t->consts[in->op2.loc];
  return fold_const(vm_runtime_math_add_slow(lhs, rhs));
}

IRFOLD(MUL CONST CONST)
IRFOLDF(fold_mul_const_const) {
  auto lhs = t->consts[in->op1.loc];
  auto rhs = t->consts[in->op2.loc];
  return fold_const(vm_runtime_math_mul_slow(lhs, rhs));
}

IRFOLD(QUOTIENT CONST CONST)
IRFOLDF(fold_quotient_const_const) {
  auto lhs = t->consts[in->op1.loc];
  auto rhs = t->consts[in->op2.loc];
  return fold_const(vm_runtime_math_quotient_slow(lhs, rhs));
}

IRFOLD(MOD CONST CONST)
IRFOLDF(fold_mod_const_const) {
  auto lhs = t->consts[in->op1.loc];
  auto rhs = t->consts[in->op2.loc];
  return fold_const(vm_runtime_math_mod_slow(lhs, rhs));
}

IRFOLD(LOAD CONST CONST)
IRFOLDF(fold_load_const_const) {
  auto src = t->consts[in->op1.loc];
  auto off = t->consts[in->op2.loc];
  if (get_type_tag(src) != CLOSURE_TAG) {
    return fold_next();
  }
  assert(is_heap_object(src));
  assert(is_fixnum(off));

  auto base = (gc_obj *)((uint8_t *)to_raw_ptr(src) + sizeof(gc_header));
  return fold_const(base[to_fixnum(off)]);
}

#undef cur_ins

#include "fold_gen.h"

static fold_result fold_one(trace *t, ir_ins *in) {
  uint32_t key = fold_key(t, in);
  uint32_t any = 0;
  for (;;) {
    uint32_t k = key | any;
    uint32_t h = hashkey(k);
    uint32_t fh = fold_hash[h];
    if ((fh & 0xffffff) == k) {
      auto res = fold_func_table[fh >> 24](t, in);
      if (res.action != FOLD_NEXT) {
        return res;
      }
    }
    if (any == 0xffff) {
      return fold_next();
    }
    any = (any | (any >> 8)) ^ 0xff00;
  }
}

fold_result fold_instr(trace *trace, ir_ins *in) {
  for (;;) {
    fold_result res = fold_one(trace, in);
    if (res.action == FOLD_RETRY) {
      continue;
    }
    return res;
  }
}
