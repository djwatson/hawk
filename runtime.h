#pragma once

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>

#include "bigint.h"
#include "gc.h"
#include "hawk.h"
#include "types.h"

static inline gc_obj vm_box_flonum(double x) {
  flonum_s *res = gc_alloc(sizeof(flonum_s));
  res->header.type = FLONUM_TAG;
  res->x = x;
  return tag_flonum(res);
}

static inline gc_obj root1_box_flonum(gc_obj *v, double x) {
  gc_add_root((const void *)v, 1, 0);
  gc_obj res = vm_box_flonum(x);
  gc_remove_root((const void *)v, 0);
  return res;
}

static inline gc_obj root2_box_flonum(gc_obj *lhs, gc_obj *rhs, double x) {
  gc_add_root((const void *)lhs, 1, 0);
  gc_add_root((const void *)rhs, 1, 0);
  gc_obj res = vm_box_flonum(x);
  gc_remove_root((const void *)rhs, 0);
  gc_remove_root((const void *)lhs, 0);
  return res;
}

static inline double bignum_to_double(gc_obj v) {
  assert(is_bignum(v));
  bn_t *bn = to_bignum(v);
  bn_i64_result_t i64 = bn_to_i64(bn);
  if (i64.ok) {
    return (double)i64.value;
  }
  char *str = bn_to_string(bn, 10);
  if (!str) {
    abort();
  }
  double d = strtod(str, nullptr);
  free(str);
  return d;
}

static inline gc_obj numeric_to_bignum_obj(gc_obj v) {
  if (is_bignum(v)) {
    return v;
  }
  if (is_fixnum(v)) {
    return tag_bignum(bn_from_i64(to_fixnum(v)));
  }
  abort();
}

#define VM_MATH_ADD(a, b) ((a) + (b))
#define VM_MATH_SUB(a, b) ((a) - (b))
#define VM_MATH_MUL(a, b) ((a) * (b))
#define VM_MATH_NOSHIFT(a) (a)
#define VM_MATH_SHIFT(a) ((a) >> FIXNUM_SHIFT)

#define DEFINE_VM_RUNTIME_OVERFLOW_SLOW(name, oplcname, op, shift)            \
  static inline gc_obj vm_runtime_math_##name##_slow(gc_obj v1, gc_obj v2) {  \
    if (is_flonum(v1) || is_flonum(v2)) {                                      \
      return root2_box_flonum(&v1, &v2,                                        \
                              op(numeric_to_double(v1), numeric_to_double(v2))); \
    }                                                                          \
    if (is_fixnum(v1) && is_fixnum(v2)) {                                      \
      gc_obj res;                                                              \
      if (!__builtin_##oplcname##_overflow(v1.value, shift(v2.value),          \
                                           &res.value)) {                      \
        return res;                                                            \
      }                                                                        \
    }                                                                          \
    gc_add_root((const void *)&v1, 1, 0);                                      \
    gc_add_root((const void *)&v2, 1, 0);                                      \
    gc_obj b1 = numeric_to_bignum_obj(v1);                                     \
    gc_add_root((const void *)&b1, 1, 0);                                      \
    gc_obj b2 = numeric_to_bignum_obj(v2);                                     \
    gc_add_root((const void *)&b2, 1, 0);                                      \
    gc_obj res = tag_bignum(bn_##oplcname(to_bignum(b1), to_bignum(b2)));      \
    gc_remove_root((const void *)&b2, 0);                                      \
    gc_remove_root((const void *)&b1, 0);                                      \
    gc_remove_root((const void *)&v2, 0);                                      \
    gc_remove_root((const void *)&v1, 0);                                      \
    return res;                                                                \
  }

static inline double numeric_to_double(gc_obj v) {
  if (is_flonum(v)) {
    return to_flonum(v)->x;
  }
  if (is_fixnum(v)) {
    return (double)to_fixnum(v);
  }
  if (is_bignum(v)) {
    return bignum_to_double(v);
  }
  abort();
}

static inline gc_obj numeric_inexact_value(gc_obj v) {
  if (is_fixnum(v)) {
    return root1_box_flonum(&v, (double)to_fixnum(v));
  }
  if (is_flonum(v)) {
    return v;
  }
  if (is_bignum(v)) {
    return root1_box_flonum(&v, bignum_to_double(v));
  }
  abort();
}

static inline gc_obj numeric_exact_value(gc_obj v) {
  if (is_fixnum(v)) {
    return v;
  }
  if (is_bignum(v)) {
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
  if (is_bignum(v)) {
    return v;
  }
  if (is_flonum(v)) {
    return root1_box_flonum(&v, trunc(to_flonum(v)->x));
  }
  abort();
}

DEFINE_VM_RUNTIME_OVERFLOW_SLOW(add, add, VM_MATH_ADD, VM_MATH_NOSHIFT)
DEFINE_VM_RUNTIME_OVERFLOW_SLOW(sub, sub, VM_MATH_SUB, VM_MATH_NOSHIFT)
DEFINE_VM_RUNTIME_OVERFLOW_SLOW(mul, mul, VM_MATH_MUL, VM_MATH_SHIFT)

#undef DEFINE_VM_RUNTIME_OVERFLOW_SLOW

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

static inline bool numeric_eqv(gc_obj lhs, gc_obj rhs) {
  VM_NUMERIC_DISPATCH_VALUES(lhs, rhs, return to_fixnum(lhs) == to_fixnum(rhs);
                             , return numeric_to_double(lhs) ==
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

#define VM_FOLD_NUMERIC_CONST_BINOP(lhs, rhs, fixnum_body, flonum_body)        \
  do {                                                                         \
    if (numeric_obj_result_type((lhs), (rhs)) == FLONUM_TAG) {                 \
      return fold_const(root2_box_flonum(&(lhs), &(rhs), (flonum_body)));      \
    }                                                                          \
    return fold_const(tag_fixnum(fixnum_body));                                \
  } while (0)

static inline bool guard_obj_matches(gc_obj val, gc_obj want_tag_obj) {
  assert(is_fixnum(want_tag_obj));
  uint64_t want_tag = (uint64_t)to_fixnum(want_tag_obj);

  if ((want_tag & TAG_MASK) == PTR_TAG) {
    return is_ptr(val) && ((want_tag == PTR_TAG) || get_type_tag(val) == want_tag);
  }

  uint64_t got_tag = (uint64_t)get_type_tag(val);
  if (got_tag == LITERAL_TAG) {
    return (((uint64_t)val.value & IMMEDIATE_MASK) == want_tag);
  }
  return got_tag == want_tag;
}
