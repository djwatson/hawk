#include "opt_loop.h"

#include <stdlib.h>
#include <string.h>

#include "runtime.h"

static bool same_slot(slot a, slot b) { return memcmp(&a, &b, sizeof(a)) == 0; }

static uint8_t slot_type(trace *t, slot v) {
  return v.constant ? get_type_tag(t->consts[v.loc]) : t->ins[v.loc].type;
}

// Ranges describe mathematical, untagged values on the successful path.
typedef struct { __int128 lo, hi; } int_range;

static int_range value_range(trace *t, int_range *ranges, slot v) {
  if (!v.constant)
    return ranges[v.loc];
  if (is_fixnum(t->consts[v.loc])) {
    int64_t k = to_fixnum(t->consts[v.loc]);
    return (int_range){k, k};
  }
  return (int_range){FIXNUM_MIN_VALUE, FIXNUM_MAX_VALUE};
}

static void constrain(int_range *ranges, slot v, int_range r) {
  if (!v.constant) {
    if (r.lo > ranges[v.loc].lo) ranges[v.loc].lo = r.lo;
    if (r.hi < ranges[v.loc].hi) ranges[v.loc].hi = r.hi;
  }
}

typedef struct { slot index, object; } array_bound;

static bool has_bound(array_bound *bounds, slot index, slot object) {
  arr_for_each(bounds, b) {
    if (same_slot(b.index, index) && same_slot(b.object, object)) return true;
  }
  return false;
}

static void add_bound(array_bound **bounds, slot index, slot object) {
  if (!has_bound(*bounds, index, object))
    arrput(*bounds, ((array_bound){index, object}));
}

static bool monotone_step(trace *t, slot result, slot input, bool descending) {
  if (same_slot(result, input)) return true;
  if (result.constant) return false;
  auto in = &t->ins[result.loc];
  if (in->type != FIXNUM_TAG ||
      (in->op != IR_ADD && in->op != IR_ADD_UNCHECKED &&
       in->op != IR_SUB && in->op != IR_SUB_UNCHECKED) ||
      !same_slot(in->op1, input) || !in->op2.constant) return false;
  __int128 delta = to_fixnum(t->consts[in->op2.loc]);
  if (in->op == IR_SUB || in->op == IR_SUB_UNCHECKED) delta = -delta;
  return descending ? delta <= 0 : delta >= 0;
}

static bool phi_changes(trace *t, slot value) {
  arr_for_each(t->ins, in) {
    if (in.op == IR_PHI && same_slot(in.op1, value)) return true;
  }
  return false;
}

// Prove that stores in the repeated body cannot change a vector's length.
static bool stable_lengths(trace *t) {
  for (size_t i = t->loop_body_ir; i < arrlen(t->ins); i++) {
    auto in = &t->ins[i];
    if (in->op == IR_CCALL || in->op == IR_CALLCC ||
        in->op == IR_CALLCC_RESUME || in->op == IR_FLUSH) return false;
    if (in->op != IR_STORE) continue;
    if (in->type != VECTOR_TAG && in->type != UNDEFINED_TAG) continue;
    auto ref = &t->ins[in->op1.loc];
    if (ref->op2.constant && to_fixnum(t->consts[ref->op2.loc]) > 0) continue;
    if (ref->op2.constant || phi_changes(t, ref->op2)) return false;
    auto offset = &t->ins[ref->op2.loc];
    if (ref->op2.loc < t->loop_body_ir && phi_changes(t, offset->op1))
      return false;
    if ((offset->op != IR_ADD && offset->op != IR_ADD_UNCHECKED) ||
        !offset->op2.constant || to_fixnum(t->consts[offset->op2.loc]) < 1)
      return false;
    bool checked = false;
    for (size_t j = t->loop_body_ir; j < i; j++) {
      if (t->ins[j].op == IR_ABC && same_slot(t->ins[j].op2, offset->op1))
        checked = true;
    }
    if (!checked) return false;
  }
  return true;
}

void opt_ranges(trace *t) {
  size_t n = arrlen(t->ins);
  int_range full = {FIXNUM_MIN_VALUE, FIXNUM_MAX_VALUE};
  int_range *ranges = malloc(n * sizeof(*ranges));
  if (!ranges && n) abort();
  for (size_t i = 0; i < n; i++) ranges[i] = full;
  array_bound *bounds = nullptr;
  size_t length_epoch = 0;
  bool stable = stable_lengths(t);
  for (size_t i = 0; i < n; i++) {
    if (i == t->loop_body_ir) {
      size_t kept = 0;
      arr_for_each(bounds, b) {
        bool keep = stable && !phi_changes(t, b.object);
        arr_for_each(t->ins, phi) {
          if (phi.op == IR_PHI && same_slot(phi.op1, b.index))
            keep &= !phi_changes(t, phi.op2) &&
                    monotone_step(t, phi.op2, phi.op1, true);
        }
        if (keep) bounds[kept++] = b;
      }
      arrlen_set(bounds, kept);
      if (!stable) length_epoch = i;
      arr_for_each(t->ins, phi) {
        if (phi.op == IR_PHI) {
          bool nonnegative = ranges[phi.op1.loc].lo >= 0 &&
              ranges[phi.op1.loc].lo <= ranges[phi.op1.loc].hi &&
              !phi_changes(t, phi.op2) &&
              monotone_step(t, phi.op2, phi.op1, false);
          ranges[phi.op1.loc] = full;
          if (nonnegative) ranges[phi.op1.loc].lo = 0;
        }
      }
    }
    ir_ins *in = &t->ins[i];
    if (in->op == IR_LOAD_BYTE) ranges[i] = (int_range){0, 255};
    if (in->op == IR_CCALL || in->op == IR_CALLCC ||
        in->op == IR_CALLCC_RESUME || in->op == IR_FLUSH ||
        (in->op == IR_STORE &&
         (in->type == VECTOR_TAG || in->type == UNDEFINED_TAG) &&
         value_range(t, ranges, t->ins[in->op1.loc].op2).lo < 1)) {
      arrlen_set(bounds, 0);
      length_epoch = i + 1;
    }
    if (in->op == IR_ABC) {
      if (in->type == VECTOR_TAG) {
        if (value_range(t, ranges, in->op2).lo >= 0 &&
            has_bound(bounds, in->op2, in->op1)) {
          in->op = IR_NOP;
          in->guard = false;
        }
        add_bound(&bounds, in->op2, in->op1);
      }
      constrain(ranges, in->op2, (int_range){0, FIXNUM_MAX_VALUE - 1});
      continue;
    }
    if (in->type != FIXNUM_TAG) continue;
    if (ir_ins_types[in->op] != IR_ARG_IR_IR) continue;
    int_range a = value_range(t, ranges, in->op1);
    int_range b = value_range(t, ranges, in->op2);
    if (a.lo > a.hi || b.lo > b.hi) continue;
    if (in->op >= IR_LT && in->op <= IR_GTE) {
      if (in->op == IR_GT || in->op == IR_GTE) {
        int_range tmp = a; a = b; b = tmp;
      }
      int strict = in->op == IR_LT || in->op == IR_GT;
      slot lhs = in->op == IR_GT || in->op == IR_GTE ? in->op2 : in->op1;
      slot rhs = in->op == IR_GT || in->op == IR_GTE ? in->op1 : in->op2;
      constrain(ranges, lhs, (int_range){full.lo, b.hi - strict});
      constrain(ranges, rhs, (int_range){a.lo + strict, full.hi});
      if (strict && !rhs.constant && rhs.loc >= length_epoch &&
          !phi_changes(t, rhs)) {
        auto len = &t->ins[rhs.loc];
        if (len->op == IR_LOAD && len->op2.constant &&
            to_fixnum(t->consts[len->op2.loc]) == 0 &&
            slot_type(t, len->op1) == VECTOR_TAG &&
            !phi_changes(t, len->op1))
          add_bound(&bounds, lhs, len->op1);
      }
      continue;
    }
    int_range r;
    ir_ins_op unchecked;
    if (in->op == IR_ADD) {
      r = (int_range){a.lo + b.lo, a.hi + b.hi};
      unchecked = IR_ADD_UNCHECKED;
    } else if (in->op == IR_SUB) {
      r = (int_range){a.lo - b.hi, a.hi - b.lo};
      unchecked = IR_SUB_UNCHECKED;
    } else if (in->op == IR_MUL) {
      __int128 products[] = {a.lo*b.lo, a.lo*b.hi, a.hi*b.lo, a.hi*b.hi};
      r = (int_range){products[0], products[0]};
      for (size_t j = 1; j < 4; j++) {
        if (products[j] < r.lo) r.lo = products[j];
        if (products[j] > r.hi) r.hi = products[j];
      }
      unchecked = IR_MUL_UNCHECKED;
    } else continue;
    if (a.lo <= a.hi && b.lo <= b.hi && r.lo >= full.lo && r.hi <= full.hi)
      in->op = unchecked;
    if (in->op == unchecked) in->guard = false;
    if (r.lo < full.lo) r.lo = full.lo;
    if (r.hi > full.hi) r.hi = full.hi;
    ranges[i] = r;
    size_t count = arrlen(bounds);
    for (size_t j = 0; j < count; j++) {
      if (monotone_step(t, (slot){.loc = (uint16_t)i}, bounds[j].index, true))
        add_bound(&bounds, (slot){.loc = (uint16_t)i}, bounds[j].object);
    }
  }
  arrfree(bounds);
  free(ranges);
}

