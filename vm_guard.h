#pragma once

#include <assert.h>
#include <stdlib.h>

#include "gc.h"
#include "types.h"

static inline gc_obj vm_box_flonum(double x) {
  flonum_s *res = gc_alloc(sizeof(flonum_s));
  res->header.type = FLONUM_TAG;
  res->x = x;
  return tag_flonum(res);
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

#define DEFINE_VM_RUNTIME_NUMERIC_BINOP(name, fixnum_body, flonum_body,        \
                                        fallback_body)                         \
  static inline gc_obj emit_ov_math_##name(vm_state *state, gc_obj v1,         \
                                           gc_obj v2) {                        \
    if (likely((is_fixnum(v1) & is_fixnum(v2)) == 1)) {                        \
      fixnum_body                                                              \
    }                                                                          \
    if (likely((is_flonum(v1) & is_flonum(v2)) == 1)) {                        \
      flonum_body                                                              \
    }                                                                          \
    fallback_body                                                              \
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
