#pragma once

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>

#include "bigint.h"
#include "gc.h"
#include "types.h"

static inline bool numeric_is_zero(gc_obj v) {
  if (is_fixnum(v)) {
    return to_fixnum(v) == 0;
  }
  if (is_flonum(v)) {
    return to_flonum(v)->x == 0.0;
  }
  if (is_bignum(v)) {
    return bn_is_zero(to_bignum(v));
  }
  if (is_ratnum(v)) {
    return numeric_is_zero(to_ratnum(v)->num);
  }
  abort();
}

static INLINE inline bool guard_obj_matches(gc_obj val, gc_obj want_tag_obj) {
  assert(is_fixnum(want_tag_obj));
  uint64_t want_tag = (uint64_t)to_fixnum(want_tag_obj);

  if ((want_tag & TAG_MASK) == PTR_TAG) {
    return is_ptr(val) &&
           ((want_tag == PTR_TAG) || get_type_tag(val) == want_tag);
  }

  uint64_t got_tag = (uint64_t)get_type_tag(val);
  if (got_tag == LITERAL_TAG) {
    return (((uint64_t)val.value & IMMEDIATE_MASK) == want_tag);
  }
  return got_tag == want_tag;
}

static INLINE inline bool guardmask_obj_matches(gc_obj val, uint64_t mask,
                                                uint64_t expected) {
  if (!is_fixnum(val) && !is_literal(val)) {
    auto hdr = *(uint32_t *)(val.value & ~(int64_t)TAG_MASK);
    return ((hdr & mask) == expected);
  }
  if (is_fixnum(val))
    return ((FIXNUM_TAG & mask) == expected);
  return (((uint64_t)val.value & IMMEDIATE_MASK & mask) == expected);
}

#define VM_MATH_ADD(a, b) ((a) + (b))
#define VM_MATH_SUB(a, b) ((a) - (b))
#define VM_MATH_MUL(a, b) ((a) * (b))
#define VM_MATH_NOSHIFT(a) (a)
#define VM_MATH_SHIFT(a) ((a) >> FIXNUM_SHIFT)

gc_obj SCM_MAKE_RECTANGULAR(gc_obj real, gc_obj imag);
gc_obj get_compnum(gc_obj v);
gc_obj SCM_REAL_PART(gc_obj comp);
gc_obj SCM_IMAG_PART(gc_obj comp);
gc_obj vm_box_flonum(double x);
double bignum_to_double(gc_obj v);
gc_obj numeric_to_bignum_obj(gc_obj v);
int numeric_exact_compare(gc_obj v1, gc_obj v2);
double numeric_to_double(gc_obj v);
gc_obj numeric_inexact_value(gc_obj v);
gc_obj numeric_exact_value(gc_obj v);
gc_obj numeric_truncate_value(gc_obj v);
bool numeric_fixnum_floatable_wlop(gc_obj v);
int numeric_real_compare(gc_obj lhs, gc_obj rhs, bool *ordered);

gc_obj vm_runtime_math_add_slow(gc_obj v1, gc_obj v2);
gc_obj vm_runtime_math_sub_slow(gc_obj v1, gc_obj v2);
gc_obj vm_runtime_math_mul_slow(gc_obj v1, gc_obj v2);
gc_obj vm_runtime_math_div_slow(gc_obj v1, gc_obj v2);
gc_obj vm_runtime_math_quotient_slow(gc_obj v1, gc_obj v2);
gc_obj vm_runtime_math_mod_slow(gc_obj v1, gc_obj v2);
gc_obj vm_runtime_cmp_lt_slow(gc_obj v1, gc_obj v2);
gc_obj vm_runtime_cmp_gt_slow(gc_obj v1, gc_obj v2);
gc_obj vm_runtime_cmp_lte_slow(gc_obj v1, gc_obj v2);
gc_obj vm_runtime_cmp_gte_slow(gc_obj v1, gc_obj v2);
gc_obj vm_runtime_cmp_jeqv_slow(gc_obj v1, gc_obj v2);
gc_obj vm_runtime_cmp_numeq_slow(gc_obj v1, gc_obj v2);
gc_obj make_string(const char *str);

static inline uint8_t numeric_result_type(uint8_t t1, uint8_t t2) {
  if (t1 == FLONUM_TAG || t2 == FLONUM_TAG) {
    return FLONUM_TAG;
  }
  if (t1 == FIXNUM_TAG && t2 == FIXNUM_TAG) {
    return FIXNUM_TAG;
  }
  abort();
}

#define VM_NUMERIC_TYPE_OF(v)                                                  \
  (is_flonum((v)) ? FLONUM_TAG : (is_fixnum((v)) ? FIXNUM_TAG : (abort(), 0)))

static inline uint8_t numeric_obj_result_type(gc_obj lhs, gc_obj rhs) {
  return numeric_result_type(VM_NUMERIC_TYPE_OF(lhs), VM_NUMERIC_TYPE_OF(rhs));
}

#define VM_NUMERIC_DISPATCH_VALUES(lhs, rhs, fixnum_body, flonum_body)         \
  do {                                                                         \
    uint8_t numeric_type__ = numeric_obj_result_type((lhs), (rhs));            \
    if (numeric_type__ == FIXNUM_TAG) {                                        \
      fixnum_body                                                              \
    }                                                                          \
    flonum_body                                                                \
  } while (0)

bool numeric_eqv(gc_obj lhs, gc_obj rhs);
bool obj_jeqv(gc_obj lhs, gc_obj rhs);
