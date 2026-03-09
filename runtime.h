#pragma once

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#include "gc.h"
#include "types.h"

static inline gc_obj vm_box_flonum(double x) {
  flonum_s *res = gc_alloc(sizeof(flonum_s));
  res->header.type = FLONUM_TAG;
  res->x = x;
  return tag_flonum(res);
}

static inline double numeric_to_double(gc_obj v) {
  if (is_flonum(v)) {
    return to_flonum(v)->x;
  }
  if (is_fixnum(v)) {
    return (double)to_fixnum(v);
  }
  abort();
}

static inline gc_obj numeric_inexact_value(gc_obj v) {
  if (is_fixnum(v)) {
    return vm_box_flonum((double)to_fixnum(v));
  }
  if (is_flonum(v)) {
    return v;
  }
  abort();
}

static inline gc_obj numeric_exact_value(gc_obj v) {
  if (is_fixnum(v)) {
    return v;
  }
  if (is_flonum(v)) {
    double x = to_flonum(v)->x;
    if (!isfinite(x) || x < (double)INT64_MIN || x > (double)INT64_MAX) {
      abort();
    }
    return tag_fixnum((int64_t)x);
  }
  abort();
}

static inline gc_obj numeric_truncate_value(gc_obj v) {
  if (is_fixnum(v)) {
    return v;
  }
  if (is_flonum(v)) {
    return vm_box_flonum(trunc(to_flonum(v)->x));
  }
  abort();
}

static inline uint8_t numeric_guard_type(uint8_t t1, uint8_t t2) {
  if (t1 == FLONUM_TAG || t2 == FLONUM_TAG) {
    return FLONUM_TAG;
  }
  if (t1 == FIXNUM_TAG && t2 == FIXNUM_TAG) {
    return FIXNUM_TAG;
  }
  abort();
}

#define VM_NUMERIC_TYPE_OF(v)                                                  \
  (is_flonum((v)) ? FLONUM_TAG                                                 \
                  : (is_fixnum((v)) ? FIXNUM_TAG : (abort(), 0)))

static inline uint8_t numeric_obj_guard_type(gc_obj lhs, gc_obj rhs) {
  return numeric_guard_type(VM_NUMERIC_TYPE_OF(lhs), VM_NUMERIC_TYPE_OF(rhs));
}

#define VM_NUMERIC_DISPATCH_VALUES(lhs, rhs, fixnum_body, flonum_body)         \
  do {                                                                         \
    uint8_t numeric_type__ = numeric_obj_guard_type((lhs), (rhs));             \
    if (numeric_type__ == FIXNUM_TAG) {                                        \
      fixnum_body                                                              \
    }                                                                          \
    flonum_body                                                                \
  } while (0)

static inline bool numeric_eqv(gc_obj lhs, gc_obj rhs) {
  VM_NUMERIC_DISPATCH_VALUES(lhs, rhs, return to_fixnum(lhs) == to_fixnum(rhs);,
                             return numeric_to_double(lhs) ==
                                    numeric_to_double(rhs););
}

static inline bool obj_jeqv(gc_obj lhs, gc_obj rhs) {
  if ((is_fixnum(lhs) || is_flonum(lhs)) &&
      (is_fixnum(rhs) || is_flonum(rhs))) {
    return numeric_eqv(lhs, rhs);
  }
  return lhs.value == rhs.value;
}

#define DEFINE_VM_RUNTIME_NUMERIC_BINOP(name, fixnum_body, flonum_body)        \
  static inline gc_obj emit_ov_math_##name(vm_state *state, gc_obj v1,         \
                                           gc_obj v2) {                        \
    (void)state;                                                               \
    VM_NUMERIC_DISPATCH_VALUES(v1, v2, fixnum_body, flonum_body);              \
  }

#define DEFINE_RECORD_NUMERIC_BINOP_SAME_TYPE(name, ir_op)                     \
  static slot emit_ov_math_##name(vm_state *state, slot v1, slot v2) {         \
    auto t = record_current_trace(state);                                      \
    if (get_slot_type(t, v1) != get_slot_type(t, v2)) {                        \
      abort();                                                                 \
    }                                                                          \
    ir_ins ins =                                                               \
        IR(.op = ir_op, .op1 = v1, .op2 = v2, .type = get_slot_type(t, v1));   \
    return add_inst(state, ins);                                               \
  }

#define DEFINE_RECORD_NUMERIC_BINOP_COERCED(name, ir_op)                       \
  static slot emit_ov_math_##name(vm_state *state, slot v1, slot v2) {         \
    auto t = record_current_trace(state);                                      \
    uint8_t type = numeric_guard_type(get_slot_type(t, v1),                    \
                                      get_slot_type(t, v2));                   \
    if (type == FLONUM_TAG) {                                                  \
      v1 = convert_to_flonum(state, v1);                                       \
      v2 = convert_to_flonum(state, v2);                                       \
    }                                                                          \
    ir_ins ins = IR(.op = ir_op, .op1 = v1, .op2 = v2, .type = type);          \
    return add_inst(state, ins);                                               \
  }

#define DEFINE_RECORD_NUMERIC_BINOP_FORCE_FLONUM(name, ir_op)                  \
  static slot emit_ov_math_##name(vm_state *state, slot v1, slot v2) {         \
    v1 = convert_to_flonum(state, v1);                                         \
    v2 = convert_to_flonum(state, v2);                                         \
    ir_ins ins =                                                               \
        IR(.op = ir_op, .op1 = v1, .op2 = v2, .type = FLONUM_TAG);             \
    return add_inst(state, ins);                                               \
  }

#define RECORD_JEQV_GUARD_TYPE(t, v1, v2, lhs, rhs)                            \
  (((is_fixnum((lhs)) || is_flonum((lhs))) &&                                  \
    (is_fixnum((rhs)) || is_flonum((rhs))))                                    \
       ? numeric_guard_type(get_slot_type((t), (v1)), get_slot_type((t), (v2)))\
       : get_slot_type((t), (v1)))

#define VM_FOLD_NUMERIC_CONST_BINOP(lhs, rhs, fixnum_body, flonum_body)        \
  do {                                                                         \
    if (numeric_obj_guard_type((lhs), (rhs)) == FLONUM_TAG) {                  \
      return fold_const(vm_box_flonum(flonum_body));                           \
    }                                                                          \
    return fold_const(tag_fixnum(fixnum_body));                                \
  } while (0)

static inline bool guard_obj_matches(gc_obj val, gc_obj want_tag_obj) {
  assert(is_fixnum(want_tag_obj));
  uint64_t want_tag = (uint64_t)to_fixnum(want_tag_obj);
  uint64_t got_tag = (uint64_t)get_type_tag(val);

  assert((want_tag & TAG_MASK) != PTR_TAG); // todo
  if (got_tag == LITERAL_TAG) {
    return (((uint64_t)val.value & IMMEDIATE_MASK) == want_tag);
  }
  return got_tag == want_tag;
}
