#include <assert.h>
#include <fcntl.h>
#include <limits.h>

#include "bigint.h"
#include "ftoa.h"
#include "gc.h"
#include "hawk.h"
#include "runtime.h"
#include "types.h"

#define FIXNUM_MAX_VALUE ((INT64_C(1) << (63 - FIXNUM_SHIFT)) - 1)
#define FIXNUM_MIN_VALUE (-(INT64_C(1) << (63 - FIXNUM_SHIFT)))

static bool fits_fixnum_i64(int64_t value) {
  return value >= FIXNUM_MIN_VALUE && value <= FIXNUM_MAX_VALUE;
}

static bool can_tag_fixnum_i64(int64_t value) {
  if (!fits_fixnum_i64(value)) {
    return false;
  }
  gc_obj tagged = tag_fixnum(value);
  return is_fixnum(tagged) && to_fixnum(tagged) == value;
}

static gc_obj normalize_exact_integer(gc_obj value) {
  if (!is_bignum(value)) {
    return value;
  }
  bn_i64_result_t i64 = bn_to_i64(to_bignum(value));
  if (i64.ok && can_tag_fixnum_i64(i64.value)) {
    return tag_fixnum(i64.value);
  }
  return value;
}

static gc_obj make_cons(gc_obj a, gc_obj b) {
  gc_add_root((const void *)&a, 1, 0);
  gc_add_root((const void *)&b, 1, 0);
  cons_s *cell = gc_alloc(sizeof(cons_s));
  cell->header.type = CONS_TAG;
  cell->a = a;
  cell->b = b;
  gc_remove_root((const void *)&b, 0);
  gc_remove_root((const void *)&a, 0);
  return tag_cons(cell);
}

EXPORT int32_t scm_open(char *name, uint8_t readonly) {
  return open(name, readonly ? O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC, 0777);
}

EXPORT char *flonum_string(double d) { return ftoa_fast(d); }
EXPORT char *bignum_string(gc_obj g) {
  assert(is_bignum(g));
  return bn_to_string(to_bignum(g), 10);
}

EXPORT gc_obj bignum_exact_integer_sqrt(gc_obj g) {
  assert(is_bignum(g));
  bn_sqrt_result_t qr = bn_sqrt(to_bignum(g));
  return make_cons(normalize_exact_integer(tag_bignum(qr.q)),
                   normalize_exact_integer(tag_bignum(qr.r)));
}

#define DEFINE_VM_RUNTIME_OVERFLOW_SLOW(name, oplcname, op, shift)            \
  gc_obj vm_runtime_math_##name##_slow(gc_obj v1, gc_obj v2) {                \
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
    gc_obj res = normalize_exact_integer(                                       \
        tag_bignum(bn_##oplcname(to_bignum(b1), to_bignum(b2))));              \
    gc_remove_root((const void *)&b2, 0);                                      \
    gc_remove_root((const void *)&b1, 0);                                      \
    gc_remove_root((const void *)&v2, 0);                                      \
    gc_remove_root((const void *)&v1, 0);                                      \
    return res;                                                                \
  }

DEFINE_VM_RUNTIME_OVERFLOW_SLOW(add, add, VM_MATH_ADD, VM_MATH_NOSHIFT)
DEFINE_VM_RUNTIME_OVERFLOW_SLOW(sub, sub, VM_MATH_SUB, VM_MATH_NOSHIFT)
DEFINE_VM_RUNTIME_OVERFLOW_SLOW(mul, mul, VM_MATH_MUL, VM_MATH_SHIFT)

#undef DEFINE_VM_RUNTIME_OVERFLOW_SLOW

gc_obj vm_runtime_math_div_slow(gc_obj v1, gc_obj v2) {
  if (numeric_is_zero(v2)) {
    abort();
  }
  return root2_box_flonum(&v1, &v2,
                          numeric_to_double(v1) / numeric_to_double(v2));
}

#define DEFINE_VM_RUNTIME_DIVMOD_SLOW(name, fixnum_body, flonum_body, field)  \
  gc_obj vm_runtime_math_##name##_slow(gc_obj v1, gc_obj v2) {                \
    if (numeric_is_zero(v2)) {                                                 \
      abort();                                                                 \
    }                                                                          \
    if (is_flonum(v1) || is_flonum(v2)) {                                      \
      return root2_box_flonum(&v1, &v2, (flonum_body));                        \
    }                                                                          \
    if (is_fixnum(v1) && is_fixnum(v2)) {                                      \
      return tag_fixnum((fixnum_body));                                        \
    }                                                                          \
    gc_add_root((const void *)&v1, 1, 0);                                      \
    gc_add_root((const void *)&v2, 1, 0);                                      \
    gc_obj b1 = numeric_to_bignum_obj(v1);                                     \
    gc_add_root((const void *)&b1, 1, 0);                                      \
    gc_obj b2 = numeric_to_bignum_obj(v2);                                     \
    gc_add_root((const void *)&b2, 1, 0);                                      \
    bn_divmod_result_t qr = bn_divmod(to_bignum(b1), to_bignum(b2));           \
    gc_obj res = normalize_exact_integer(tag_bignum(qr.field));                \
    gc_remove_root((const void *)&b2, 0);                                      \
    gc_remove_root((const void *)&b1, 0);                                      \
    gc_remove_root((const void *)&v2, 0);                                      \
    gc_remove_root((const void *)&v1, 0);                                      \
    return res;                                                                \
  }

DEFINE_VM_RUNTIME_DIVMOD_SLOW(
    quotient, to_fixnum(v1) / to_fixnum(v2),
    trunc(numeric_to_double(v1) / numeric_to_double(v2)), q)
DEFINE_VM_RUNTIME_DIVMOD_SLOW(
    mod, to_fixnum(v1) % to_fixnum(v2),
    fmod(numeric_to_double(v1), numeric_to_double(v2)), r)

#undef DEFINE_VM_RUNTIME_DIVMOD_SLOW

#define DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW(name, op)                           \
  gc_obj vm_runtime_cmp_##name##_slow(gc_obj v1, gc_obj v2) {                 \
    if (is_flonum(v1) || is_flonum(v2)) {                                      \
      return (numeric_to_double(v1) op numeric_to_double(v2)) ? TRUE_REP       \
                                                              : FALSE_REP;      \
    }                                                                          \
    if (is_fixnum(v1) && is_fixnum(v2)) {                                      \
      return (to_fixnum(v1) op to_fixnum(v2)) ? TRUE_REP : FALSE_REP;          \
    }                                                                          \
    if ((is_fixnum(v1) || is_bignum(v1)) &&                                    \
        (is_fixnum(v2) || is_bignum(v2))) {                                    \
      return (numeric_exact_compare(v1, v2) op 0) ? TRUE_REP : FALSE_REP;      \
    }                                                                          \
    abort();                                                                   \
  }

DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW(lt, <)
DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW(gt, >)
DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW(lte, <=)
DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW(gte, >=)

#undef DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW

gc_obj vm_runtime_cmp_jeqv_slow(gc_obj v1, gc_obj v2) {
  return obj_jeqv(v1, v2) ? TRUE_REP : FALSE_REP;
}
