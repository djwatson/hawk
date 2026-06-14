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
static fold_result fold_ref(slot ref) {
  return (fold_result){.action = FOLD_REF, .ref = ref};
}
static fold_result fold_retry(void) {
  return (fold_result){.action = FOLD_RETRY};
}

static bool numeric_is_one(gc_obj v) {
  if (is_fixnum(v))
    return to_fixnum(v) == 1;
  if (is_flonum(v))
    return to_flonum(v)->x == 1.0;
  return false;
}

static bool is_neg_zero(trace *t, slot s, slot *out) {
  if (s.constant)
    return false;
  ir_ins *ir = &t->ins[s.loc];
  if (ir->op != IR_SUB)
    return false;
  if (!ir->op1.constant)
    return false;
  if (!numeric_is_zero(t->consts[ir->op1.loc]))
    return false;
  *out = ir->op2;
  return true;
}

static slot make_fixnum_inst(trace *t, int64_t val) {
  gc_obj const_val = tag_fixnum(val);
  uint16_t const_idx = arrlen(t->consts);
  arrput(t->consts, const_val);
  auto ins = (ir_ins){
      .op = IR_CONST,
      .type = FIXNUM_TAG,
      .guard = false,
      .reg = REG_NONE,
      .spill = SPILL_NONE,
      .op1 = {.constant = true, .loc = const_idx},
  };
  uint16_t idx = arrlen(t->ins);
  arrput(t->cse_prev, UINT16_MAX);
  arrput(t->ins, ins);
  return (slot){.constant = false, .loc = idx};
}

static bool same_slot(trace *t, slot a, slot b) {
  if (a.constant != b.constant) {
    return false;
  }
  if (!a.constant) {
    return a.loc == b.loc;
  }
  return t->consts[a.loc].value == t->consts[b.loc].value;
}

static bool fold_cse_allowed(trace *t __attribute__((unused)), ir_ins *in) {
  switch (in->op) {
  case IR_EQ:
  case IR_NE:
  case IR_LT:
  case IR_GT:
  case IR_LTE:
  case IR_GTE:
  case IR_ABC:
  case IR_ADD:
  case IR_SUB:
  case IR_MUL:
  case IR_DIV:
  case IR_QUOTIENT:
  case IR_MOD:
  case IR_BOX_FLONUM:
  case IR_EXACT:
  case IR_INTEGER_CHAR:
  case IR_CHAR_INTEGER:
  case IR_TRUNCATE:
  case IR_INEXACT:
  case IR_VMINEXACT:
  case IR_VMEXACT:
  case IR_VMTRUNCATE:
  case IR_LOAD:
  case IR_LOAD_CHAR:
  case IR_LOAD_BYTE:
  case IR_GGET:
    return true;
  default:
    return false;
  }
}

static bool const_slot_eq(trace *t, slot a, slot b) {
  assert(a.constant && b.constant);
  return t->consts[a.loc].value == t->consts[b.loc].value;
}

static bool store_invalidates_load(trace *t, ir_ins *load, ir_ins *store,
                                   ir_ins_op store_op) {
  assert(store->op == store_op);
  if (!load->op2.constant || store->op1.constant) {
    return true;
  }

  ir_ins *store_ref = &t->ins[store->op1.loc];
  if (store_ref->op != IR_REF || !store_ref->op2.constant) {
    return true;
  }
  return const_slot_eq(t, load->op2, store_ref->op2);
}

static bool load_cse_allowed(trace *t, uint16_t load_ref, ir_ins_op store_op) {
  ir_ins *load = &t->ins[load_ref];
  uint16_t store_ref = t->cse_head[store_op];
  while (store_ref != UINT16_MAX) {
    if (store_ref > load_ref &&
        store_invalidates_load(t, load, &t->ins[store_ref], store_op)) {
      return false;
    }
    store_ref = t->cse_prev[store_ref];
  }
  return true;
}

static fold_result fold_forward_load(trace *t, ir_ins *load,
                                     ir_ins_op store_op) {
  if (!load->op2.constant) {
    return fold_next();
  }

  uint16_t store_ref = t->cse_head[store_op];
  while (store_ref != UINT16_MAX) {
    ir_ins *store = &t->ins[store_ref];
    if (store->op1.constant) {
      return fold_next();
    }

    ir_ins *ref = &t->ins[store->op1.loc];
    if (ref->op != IR_REF || !ref->op2.constant) {
      return fold_next();
    }
    if (!const_slot_eq(t, load->op2, ref->op2)) {
      store_ref = t->cse_prev[store_ref];
      continue;
    }
    if (same_slot(t, load->op1, ref->op1)) {
      return fold_ref(store->op2);
    }
    return fold_next();
  }
  return fold_next();
}

static bool gset_invalidates_gget(trace *t, ir_ins *gget, ir_ins *gset) {
  assert(gset->op == IR_GSET);
  if (!gget->op1.constant || !gset->op1.constant) {
    return true;
  }
  return const_slot_eq(t, gget->op1, gset->op1);
}

static bool gget_cse_allowed(trace *t, uint16_t gget_ref) {
  ir_ins *gget = &t->ins[gget_ref];
  uint16_t gset_ref = t->cse_head[IR_GSET];
  while (gset_ref != UINT16_MAX) {
    if (gset_ref > gget_ref &&
        gset_invalidates_gget(t, gget, &t->ins[gset_ref])) {
      return false;
    }
    gset_ref = t->cse_prev[gset_ref];
  }
  return true;
}

static fold_result fold_forward_gget(trace *t, ir_ins *gget) {
  uint16_t gset_ref = t->cse_head[IR_GSET];
  while (gset_ref != UINT16_MAX) {
    ir_ins *gset = &t->ins[gset_ref];
    if (!gget->op1.constant || !gset->op1.constant) {
      return fold_next();
    }
    if (const_slot_eq(t, gget->op1, gset->op1)) {
      return fold_ref(gset->op2);
    }
    gset_ref = t->cse_prev[gset_ref];
  }
  return fold_next();
}

static bool same_cse_operands(trace *t, ir_ins *a, ir_ins *b) {
  if (a->type != b->type) {
    return false;
  }
  switch (ir_ins_types[a->op]) {
  case IR_ARG_NONE_NONE:
    return true;
  case IR_ARG_STACK:
  case IR_ARG_REG:
  case IR_ARG_PMOV:
  case IR_ARG_OFFSET:
    return a->data == b->data;
  case IR_ARG_IR_NONE:
  case IR_ARG_IR_ADDR:
    return same_slot(t, a->op1, b->op1);
  case IR_ARG_IR_IR:
    return same_slot(t, a->op1, b->op1) && same_slot(t, a->op2, b->op2);
  }
  abort();
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
  arrput(t->cse_prev, UINT16_MAX);
  arrput(t->ins, const_op);
  in->op1 = (slot){.constant = false, .loc = idx};
  return fold_retry();
}

IRFOLD(NE _ _)
IRFOLDF(fold_guard_neq_any_const) {
  bool rhs_flonum = false;
  if (in->op2.constant) {
    rhs_flonum = is_flonum(t->consts[in->op2.loc]);
  } else {
    rhs_flonum = t->ins[in->op2.loc].type == FLONUM_TAG;
  }
  bool lhs_flonum = false;
  if (in->op1.constant) {
    lhs_flonum = is_flonum(t->consts[in->op1.loc]);
  } else {
    lhs_flonum = t->ins[in->op1.loc].type == FLONUM_TAG;
  }
  if (rhs_flonum != lhs_flonum) {
    return fold_drop();
  }
  return fold_next();
}

IRFOLD(GCLOG _ _)
IRFOLDF(fold_gclog_alloc) {
  if (!in->op1.constant && t->ins[in->op1.loc].op == IR_ALLOC) {
    uint16_t alloc_ref = t->cse_head[IR_ALLOC];
    uint16_t box_ref = t->cse_head[IR_BOX_FLONUM];
    if ((alloc_ref == UINT16_MAX || alloc_ref <= in->op1.loc) &&
        (box_ref == UINT16_MAX || box_ref <= in->op1.loc)) {
      *in = (ir_ins){.op = IR_NOP, .reg = REG_NONE, .spill = SPILL_NONE};
    }
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

IRFOLD(LOAD_BYTE CONST CONST)
IRFOLDF(fold_load_byte_const_const) {
  auto src = t->consts[in->op1.loc];
  auto off = t->consts[in->op2.loc];
  if (get_type_tag(src) != BYTEVECTOR_TAG) {
    return fold_next();
  }
  assert(is_bytevector(src));
  assert(is_fixnum(off));
  auto base = (string_s *)to_bytevector(src);
  assert(to_fixnum(off) >= 0 && to_fixnum(off) < to_fixnum(base->len));
  return fold_const(tag_fixnum((uint8_t)base->str[to_fixnum(off)]));
}

IRFOLD(INTEGER_CHAR CONST _)
IRFOLDF(fold_integer_char_const) {
  if (!in->op1.constant)
    return fold_next();
  gc_obj k = t->consts[in->op1.loc];
  if (!is_fixnum(k))
    return fold_next();
  char c = (char)to_fixnum(k);
  return fold_const(tag_char(c));
}

IRFOLD(CHAR_INTEGER CONST _)
IRFOLDF(fold_char_integer_const) {
  if (!in->op1.constant)
    return fold_next();
  gc_obj c = t->consts[in->op1.loc];
  if (!is_char(c))
    return fold_next();
  return fold_const(tag_fixnum(to_char(c)));
}

// Self-comparison elimination for EQ/NE/order comparisons.
IRFOLD(EQ _ _)
IRFOLD(LT _ _)
IRFOLD(GT _ _)
IRFOLD(LTE _ _)
IRFOLD(GTE _ _)
IRFOLDF(fold_self_cmp) {
  bool same = in->op1.constant == in->op2.constant &&
              (!in->op1.constant ||
               t->consts[in->op1.loc].value == t->consts[in->op2.loc].value) &&
              (in->op1.constant || in->op1.loc == in->op2.loc);
  if (!same)
    return fold_next();
  switch (in->op) {
  case IR_EQ:
    return fold_drop();
  case IR_LT:
    return fold_next();
  case IR_GT:
    return fold_next();
  case IR_LTE:
    return fold_drop();
  case IR_GTE:
    return fold_drop();
  default:
    return fold_next();
  }
}

// ========== Category E-G: Algebraic Simplifications ==========

// Double-negation elimination: SUB(0, SUB(0, x)) -> x
IRFOLD(SUB CONST SUB)
IRFOLDF(fold_double_neg) {
  if (!in->op1.constant)
    return fold_next();
  if (!numeric_is_zero(t->consts[in->op1.loc]))
    return fold_next();
  slot inner;
  if (!is_neg_zero(t, in->op2, &inner))
    return fold_next();
  return fold_ref(inner);
}

// (-a) + b -> b - a
IRFOLD(ADD SUB _)
IRFOLDF(fold_add_neg_lhs) {
  slot a;
  if (!is_neg_zero(t, in->op1, &a))
    return fold_next();
  in->op = IR_SUB;
  in->op1 = in->op2;
  in->op2 = a;
  return fold_retry();
}

// a + (-b) -> a - b
IRFOLD(ADD _ SUB)
IRFOLDF(fold_add_neg_rhs) {
  slot b;
  if (!is_neg_zero(t, in->op2, &b))
    return fold_next();
  in->op = IR_SUB;
  in->op2 = b;
  return fold_retry();
}

// SUB x, CONST(0) -> x
IRFOLD(SUB _ CONST)
IRFOLDF(fold_sub_zero) {
  if (!in->op2.constant)
    return fold_next();
  if (!numeric_is_zero(t->consts[in->op2.loc]))
    return fold_next();
  return fold_ref(in->op1);
}

// a - (-b) -> a + b
IRFOLD(SUB _ SUB)
IRFOLDF(fold_sub_neg_rhs) {
  slot b;
  if (!is_neg_zero(t, in->op2, &b))
    return fold_next();
  in->op = IR_ADD;
  in->op2 = b;
  return fold_retry();
}

// (-x) - k -> (-k) - x  (fixnum only)
IRFOLD(SUB SUB CONST)
IRFOLDF(fold_sub_neg_lhs_const) {
  if (!in->op2.constant)
    return fold_next();
  slot x;
  if (!is_neg_zero(t, in->op1, &x))
    return fold_next();
  gc_obj k = t->consts[in->op2.loc];
  if (!is_fixnum(k))
    return fold_next();
  slot neg_k = make_fixnum_inst(t, -to_fixnum(k));
  in->op1 = neg_k;
  in->op2 = x;
  return fold_retry();
}

// MUL x, CONST -> identity, *(-1), *2, *0
IRFOLD(MUL _ CONST)
IRFOLDF(fold_mul_const) {
  if (!in->op2.constant)
    return fold_next();
  gc_obj k = t->consts[in->op2.loc];
  if (numeric_is_one(k))
    return fold_ref(in->op1);
  if (numeric_is_zero(k) && in->type == FIXNUM_TAG)
    return fold_const(tag_fixnum(0));
  if (is_fixnum(k) && to_fixnum(k) == -1) {
    slot zero = make_fixnum_inst(t, 0);
    slot x = in->op1;
    in->op = IR_SUB;
    in->op1 = zero;
    in->op2 = x;
    return fold_retry();
  }
  if ((is_fixnum(k) && to_fixnum(k) == 2) ||
      (is_flonum(k) && to_flonum(k)->x == 2.0)) {
    in->op = IR_ADD;
    in->op2 = in->op1;
    return fold_retry();
  }
  return fold_next();
}

// DIV/QUOTIENT x, CONST(1) -> x
IRFOLD(DIV _ CONST)
IRFOLDF(fold_div_const) {
  if (!in->op2.constant)
    return fold_next();
  if (numeric_is_one(t->consts[in->op2.loc]))
    return fold_ref(in->op1);
  return fold_next();
}

IRFOLD(QUOTIENT _ CONST)
IRFOLDF(fold_quotient_const) {
  if (!in->op2.constant)
    return fold_next();
  if (numeric_is_one(t->consts[in->op2.loc]))
    return fold_ref(in->op1);
  return fold_next();
}

// (-a) * k -> a * (-k)  (fixnum only)
IRFOLD(MUL SUB _)
IRFOLDF(fold_mul_neg_lhs) {
  slot a;
  if (!is_neg_zero(t, in->op1, &a))
    return fold_next();
  if (!in->op2.constant)
    return fold_next();
  gc_obj k = t->consts[in->op2.loc];
  if (!is_fixnum(k))
    return fold_next();
  slot neg_k = make_fixnum_inst(t, -to_fixnum(k));
  in->op1 = a;
  in->op2 = neg_k;
  return fold_retry();
}

// (-a) / k -> a / (-k)  (fixnum only)
IRFOLD(DIV SUB _)
IRFOLD(QUOTIENT SUB _)
IRFOLDF(fold_div_neg_lhs) {
  slot a;
  if (!is_neg_zero(t, in->op1, &a))
    return fold_next();
  if (!in->op2.constant)
    return fold_next();
  gc_obj k = t->consts[in->op2.loc];
  if (!is_fixnum(k))
    return fold_next();
  slot neg_k = make_fixnum_inst(t, -to_fixnum(k));
  in->op1 = a;
  in->op2 = neg_k;
  return fold_retry();
}

// (-a) * (-b) -> a * b, (-a) / (-b) -> a / b
IRFOLD(MUL SUB SUB)
IRFOLD(DIV SUB SUB)
IRFOLDF(fold_mul_div_neg_both) {
  slot a, b;
  if (!is_neg_zero(t, in->op1, &a))
    return fold_next();
  if (!is_neg_zero(t, in->op2, &b))
    return fold_next();
  in->op1 = a;
  in->op2 = b;
  return fold_retry();
}

// ADD x, CONST(0) -> x  (fixnum only)
IRFOLD(ADD _ CONST)
IRFOLDF(fold_add_const) {
  if (!in->op2.constant)
    return fold_next();
  if (in->type != FIXNUM_TAG)
    return fold_next();
  if (!numeric_is_zero(t->consts[in->op2.loc]))
    return fold_next();
  return fold_ref(in->op1);
}

// SUB x, x -> CONST(0)  (fixnum only)
IRFOLD(SUB _ _)
IRFOLDF(fold_sub_self) {
  if (in->type != FIXNUM_TAG)
    return fold_next();
  if (!same_slot(t, in->op1, in->op2))
    return fold_next();
  return fold_const(tag_fixnum(0));
}

// (i + j) - i -> j, (i + j) - j -> i  (fixnum only)
IRFOLD(SUB ADD _)
IRFOLDF(fold_sub_cancel_add) {
  if (in->type != FIXNUM_TAG)
    return fold_next();
  if (in->op1.constant)
    return fold_next();
  ir_ins *add = &t->ins[in->op1.loc];
  if (add->op != IR_ADD)
    return fold_next();
  if (!in->op2.constant) {
    if (in->op2.loc == add->op1.loc)
      return fold_ref(add->op2);
    if (in->op2.loc == add->op2.loc)
      return fold_ref(add->op1);
  }
  return fold_next();
}

// (i - j) - i -> 0 - j  (fixnum only)
IRFOLD(SUB SUB _)
IRFOLDF(fold_sub_cancel_sub_left) {
  if (in->type != FIXNUM_TAG)
    return fold_next();
  if (in->op1.constant)
    return fold_next();
  ir_ins *sub = &t->ins[in->op1.loc];
  if (sub->op != IR_SUB)
    return fold_next();
  if (!in->op2.constant && in->op2.loc == sub->op1.loc) {
    slot zero = make_fixnum_inst(t, 0);
    in->op1 = zero;
    in->op2 = sub->op2;
    return fold_retry();
  }
  return fold_next();
}

// i - (i - j) -> j  (fixnum only)
IRFOLD(SUB _ SUB)
IRFOLDF(fold_sub_cancel_sub_right) {
  if (in->type != FIXNUM_TAG)
    return fold_next();
  if (in->op2.constant)
    return fold_next();
  ir_ins *sub = &t->ins[in->op2.loc];
  if (sub->op != IR_SUB)
    return fold_next();
  if (!in->op1.constant && in->op1.loc == sub->op1.loc)
    return fold_ref(sub->op2);
  return fold_next();
}

// i - (i + j) -> 0 - j, i - (j + i) -> 0 - j  (fixnum only)
IRFOLD(SUB _ ADD)
IRFOLDF(fold_sub_cancel_add_right) {
  if (in->type != FIXNUM_TAG)
    return fold_next();
  if (in->op2.constant)
    return fold_next();
  ir_ins *add = &t->ins[in->op2.loc];
  if (add->op != IR_ADD)
    return fold_next();
  if (!in->op1.constant) {
    if (in->op1.loc == add->op1.loc) {
      slot zero = make_fixnum_inst(t, 0);
      in->op1 = zero;
      in->op2 = add->op2;
      return fold_retry();
    }
    if (in->op1.loc == add->op2.loc) {
      slot zero = make_fixnum_inst(t, 0);
      in->op1 = zero;
      in->op2 = add->op1;
      return fold_retry();
    }
  }
  return fold_next();
}

// (i + j) - (i + k) -> j - k, etc.  (fixnum only)
IRFOLD(SUB ADD ADD)
IRFOLDF(fold_sub_cancel_add_add) {
  if (in->type != FIXNUM_TAG)
    return fold_next();
  if (in->op1.constant || in->op2.constant)
    return fold_next();
  ir_ins *l = &t->ins[in->op1.loc];
  ir_ins *r = &t->ins[in->op2.loc];
  if (l->op != IR_ADD || r->op != IR_ADD)
    return fold_next();
  if (l->op1.loc == r->op1.loc) {
    in->op1 = l->op2;
    in->op2 = r->op2;
    return fold_retry();
  }
  if (l->op2.loc == r->op1.loc) {
    in->op1 = l->op1;
    in->op2 = r->op2;
    return fold_retry();
  }
  if (l->op1.loc == r->op2.loc) {
    in->op1 = l->op2;
    in->op2 = r->op1;
    return fold_retry();
  }
  if (l->op2.loc == r->op2.loc) {
    in->op1 = l->op1;
    in->op2 = r->op1;
    return fold_retry();
  }
  return fold_next();
}

// MOD CONST(0), any -> CONST(0)  (fixnum only)
IRFOLD(MOD CONST _)
IRFOLDF(fold_mod_zero_lhs) {
  if (!in->op1.constant)
    return fold_next();
  if (in->type != FIXNUM_TAG)
    return fold_next();
  if (!numeric_is_zero(t->consts[in->op1.loc]))
    return fold_next();
  return fold_const(tag_fixnum(0));
}

// MOD any, CONST(1) -> CONST(0)  (fixnum only)
IRFOLD(MOD _ CONST)
IRFOLDF(fold_mod_one_rhs) {
  if (!in->op2.constant)
    return fold_next();
  if (in->type != FIXNUM_TAG)
    return fold_next();
  gc_obj k = t->consts[in->op2.loc];
  if (!is_fixnum(k) || !numeric_is_one(k))
    return fold_next();
  return fold_const(tag_fixnum(0));
}

/* // ABC any CONST -> fold constant k into ABC type */
/* IRFOLD(ABC _ CONST) */
/* IRFOLDF(fold_abc_k) { */
/*   if (!in->op2.constant) */
/*     return fold_next(); */
/*   gc_obj k = t->consts[in->op2.loc]; */
/*   if (!is_fixnum(k)) */
/*     return fold_next(); */
/*   in->op1 = (slot){.constant = true, .loc = in->op2.loc}; */
/*   return fold_retry(); */
/* } */

/* // ABC any ADD -> prepare for ADD-folding */
/* IRFOLD(ABC _ ADD) */
/* IRFOLDF(fold_abc_fwd) { */
/*   if (in->op2.constant) */
/*     return fold_next(); */
/*   ir_ins *add = &t->ins[in->op2.loc]; */
/*   if (add->op != IR_ADD) */
/*     return fold_next(); */
/*   if (in->op1.constant != add->op2.constant) */
/*     return fold_next(); */
/*   return fold_next(); */
/* } */

// ========== Category H: Commutative Canonicalization ==========

// H2: ADD/MUL any, any -> swap so lower ref is on the right (for CSE)
IRFOLD(ADD _ _)
IRFOLD(MUL _ _)
IRFOLDF(fold_comm_swap) {
  if (!in->op1.constant && !in->op2.constant && in->op1.loc > in->op2.loc) {
    slot tmp = in->op1;
    in->op1 = in->op2;
    in->op2 = tmp;
    return fold_retry();
  }
  return fold_next();
}

// ========== Category I: Dead Store Elimination ==========

IRFOLD(STORE _ _)
IRFOLD(STORE_CHAR _ _)
IRFOLD(STORE_BYTE _ _)
IRFOLDF(fold_dse) {
  uint16_t store_ref = t->cse_head[in->op];
  slot store_op1 = in->op1;
  while (store_ref != UINT16_MAX) {
    ir_ins *prev = &t->ins[store_ref];
    if (prev->op == IR_NOP) {
      store_ref = t->cse_prev[store_ref];
      continue;
    }
    if (same_slot(t, prev->op1, store_op1)) {
      *prev = (ir_ins){.op = IR_NOP, .reg = REG_NONE, .spill = SPILL_NONE};
      break;
    }
    store_ref = t->cse_prev[store_ref];
  }
  return fold_next();
}

// ========== Category J: Identity folds for INEXACT/EXACT/TRUNCATE ==========
IRFOLD(INEXACT INEXACT _)
IRFOLDF(fold_inexact_inexact) { return fold_ref(in->op1); }
IRFOLD(EXACT EXACT _)
IRFOLDF(fold_exact_exact) { return fold_ref(in->op1); }
IRFOLD(TRUNCATE TRUNCATE _)
IRFOLDF(fold_truncate_truncate) { return fold_ref(in->op1); }

// INEXACT(EXACT(x)) -> x for flonum x
IRFOLD(INEXACT EXACT _)
IRFOLDF(fold_inexact_exact) {
  if (!in->op1.constant && t->ins[in->op1.loc].type == FLONUM_TAG)
    return fold_ref(t->ins[in->op1.loc].op1);
  return fold_next();
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
    if ((fh & 0xffffff) != k) {
      fh = fold_hash[h + 1];
    }
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
    if (res.action != FOLD_NEXT) {
      return res;
    }
    if (!fold_cse_allowed(trace, in)) {
      return res;
    }
    if (in->op == IR_LOAD || in->op == IR_LOAD_CHAR || in->op == IR_LOAD_BYTE) {
      ir_ins_op store_op = IR_STORE;
      if (in->op == IR_LOAD_CHAR) {
        store_op = IR_STORE_CHAR;
      } else if (in->op == IR_LOAD_BYTE) {
        store_op = IR_STORE_BYTE;
      }
      res = fold_forward_load(trace, in, store_op);
      if (res.action != FOLD_NEXT) {
        return res;
      }
    }
    if (in->op == IR_GGET) {
      res = fold_forward_gget(trace, in);
      if (res.action != FOLD_NEXT) {
        return res;
      }
    }
    uint16_t ref = trace->cse_head[in->op];
    while (ref != UINT16_MAX) {
      ir_ins *prev = &trace->ins[ref];
      bool load_op =
          in->op == IR_LOAD || in->op == IR_LOAD_CHAR || in->op == IR_LOAD_BYTE;
      if (same_cse_operands(trace, in, prev) &&
          (!load_op ||
           load_cse_allowed(trace, ref,
                            in->op == IR_LOAD        ? IR_STORE
                            : in->op == IR_LOAD_CHAR ? IR_STORE_CHAR
                                                     : IR_STORE_BYTE)) &&
          (in->op != IR_GGET || gget_cse_allowed(trace, ref))) {
        return fold_ref((slot){.constant = false, .loc = ref});
      }
      ref = trace->cse_prev[ref];
    }
    return res;
  }
}
