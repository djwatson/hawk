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

static bool exact_is_negative(gc_obj v) {
  if (is_fixnum(v)) {
    return to_fixnum(v) < 0;
  }
  if (is_bignum(v)) {
    return bn_is_negative(to_bignum(v));
  }
  abort();
}

static gc_obj exact_abs(gc_obj v) {
  if (!exact_is_negative(v)) {
    return v;
  }
  gc_add_root((const void *)&v, 1, 0);
  gc_obj res = vm_runtime_math_mul_slow(v, tag_fixnum(-1));
  gc_remove_root((const void *)&v, 0);
  return res;
}

static gc_obj exact_gcd(gc_obj a, gc_obj b) {
  while (!numeric_is_zero(b)) {
    gc_add_root((const void *)&a, 1, 0);
    gc_add_root((const void *)&b, 1, 0);
    gc_obj r = vm_runtime_math_mod_slow(a, b);
    gc_remove_root((const void *)&b, 0);
    gc_remove_root((const void *)&a, 0);
    a = b;
    b = r;
  }
  return exact_abs(a);
}

static ratnum_s get_ratnum(gc_obj v) {
  if (is_ratnum(v)) {
    return *to_ratnum(v);
  }
  if (is_fixnum(v) || is_bignum(v)) {
    return (ratnum_s){
        .header.type = RATNUM_TAG,
        .num = v,
        .denom = tag_fixnum(1),
    };
  }
  abort();
}

static gc_obj tag_ratnum(ratnum_s r) {
  gc_obj a = r.num;
  gc_obj b = r.denom;
  gc_add_root((const void *)&a, 1, 0);
  gc_add_root((const void *)&b, 1, 0);
  if (numeric_is_zero(b)) {
    gc_remove_root((const void *)&b, 0);
    gc_remove_root((const void *)&a, 0);
    abort();
  }
  bool neg = exact_is_negative(a) ^ exact_is_negative(b);
  a = exact_abs(a);
  b = exact_abs(b);
  if (numeric_is_zero(a)) {
    gc_remove_root((const void *)&b, 0);
    gc_remove_root((const void *)&a, 0);
    return a;
  }
  gc_obj g = exact_gcd(a, b);
  if (!(is_fixnum(g) && to_fixnum(g) == 1)) {
    gc_add_root((const void *)&g, 1, 0);
    a = vm_runtime_math_quotient_slow(a, g);
    b = vm_runtime_math_quotient_slow(b, g);
    gc_remove_root((const void *)&g, 0);
  }
  if (is_fixnum(b) && to_fixnum(b) == 1) {
    gc_obj res = a;
    if (neg) {
      res = vm_runtime_math_mul_slow(tag_fixnum(-1), a);
    }
    gc_remove_root((const void *)&b, 0);
    gc_remove_root((const void *)&a, 0);
    return res;
  }
  if (neg) {
    a = vm_runtime_math_mul_slow(tag_fixnum(-1), a);
  }
  ratnum_s *res = gc_alloc(sizeof(ratnum_s));
  res->header.type = RATNUM_TAG;
  res->num = a;
  res->denom = b;
  gc_remove_root((const void *)&b, 0);
  gc_remove_root((const void *)&a, 0);
  return tag_header(res, PTR_TAG);
}

static ratnum_s ratnum_add(ratnum_s a, ratnum_s b) {
  gc_add_root((const void *)&a.num, 1, 0);
  gc_add_root((const void *)&a.denom, 1, 0);
  gc_add_root((const void *)&b.num, 1, 0);
  gc_add_root((const void *)&b.denom, 1, 0);
  gc_obj p1 = vm_runtime_math_mul_slow(a.num, b.denom);
  gc_add_root((const void *)&p1, 1, 0);
  gc_obj p2 = vm_runtime_math_mul_slow(b.num, a.denom);
  gc_obj num = vm_runtime_math_add_slow(p1, p2);
  gc_add_root((const void *)&num, 1, 0);
  gc_obj denom = vm_runtime_math_mul_slow(a.denom, b.denom);
  gc_remove_root((const void *)&num, 0);
  gc_remove_root((const void *)&p1, 0);
  gc_remove_root((const void *)&b.denom, 0);
  gc_remove_root((const void *)&b.num, 0);
  gc_remove_root((const void *)&a.denom, 0);
  gc_remove_root((const void *)&a.num, 0);
  return (ratnum_s){
      .header.type = RATNUM_TAG,
      .num = num,
      .denom = denom,
  };
}

static ratnum_s ratnum_sub(ratnum_s a, ratnum_s b) {
  gc_add_root((const void *)&a.num, 1, 0);
  gc_add_root((const void *)&a.denom, 1, 0);
  gc_add_root((const void *)&b.num, 1, 0);
  gc_add_root((const void *)&b.denom, 1, 0);
  gc_obj p1 = vm_runtime_math_mul_slow(a.num, b.denom);
  gc_add_root((const void *)&p1, 1, 0);
  gc_obj p2 = vm_runtime_math_mul_slow(b.num, a.denom);
  gc_obj num = vm_runtime_math_sub_slow(p1, p2);
  gc_add_root((const void *)&num, 1, 0);
  gc_obj denom = vm_runtime_math_mul_slow(a.denom, b.denom);
  gc_remove_root((const void *)&num, 0);
  gc_remove_root((const void *)&p1, 0);
  gc_remove_root((const void *)&b.denom, 0);
  gc_remove_root((const void *)&b.num, 0);
  gc_remove_root((const void *)&a.denom, 0);
  gc_remove_root((const void *)&a.num, 0);
  return (ratnum_s){
      .header.type = RATNUM_TAG,
      .num = num,
      .denom = denom,
  };
}

static ratnum_s ratnum_mul(ratnum_s a, ratnum_s b) {
  gc_add_root((const void *)&a.num, 1, 0);
  gc_add_root((const void *)&a.denom, 1, 0);
  gc_add_root((const void *)&b.num, 1, 0);
  gc_add_root((const void *)&b.denom, 1, 0);
  gc_obj num = vm_runtime_math_mul_slow(a.num, b.num);
  gc_add_root((const void *)&num, 1, 0);
  gc_obj denom = vm_runtime_math_mul_slow(a.denom, b.denom);
  gc_remove_root((const void *)&num, 0);
  gc_remove_root((const void *)&b.denom, 0);
  gc_remove_root((const void *)&b.num, 0);
  gc_remove_root((const void *)&a.denom, 0);
  gc_remove_root((const void *)&a.num, 0);
  return (ratnum_s){
      .header.type = RATNUM_TAG,
      .num = num,
      .denom = denom,
  };
}

static ratnum_s ratnum_div(ratnum_s a, ratnum_s b) {
  gc_add_root((const void *)&a.num, 1, 0);
  gc_add_root((const void *)&a.denom, 1, 0);
  gc_add_root((const void *)&b.num, 1, 0);
  gc_add_root((const void *)&b.denom, 1, 0);
  gc_obj num = vm_runtime_math_mul_slow(a.num, b.denom);
  gc_add_root((const void *)&num, 1, 0);
  gc_obj denom = vm_runtime_math_mul_slow(a.denom, b.num);
  gc_remove_root((const void *)&num, 0);
  gc_remove_root((const void *)&b.denom, 0);
  gc_remove_root((const void *)&b.num, 0);
  gc_remove_root((const void *)&a.denom, 0);
  gc_remove_root((const void *)&a.num, 0);
  return (ratnum_s){
      .header.type = RATNUM_TAG,
      .num = num,
      .denom = denom,
  };
}

static int ratnum_cmp(ratnum_s a, ratnum_s b) {
  gc_add_root((const void *)&a.num, 1, 0);
  gc_add_root((const void *)&a.denom, 1, 0);
  gc_add_root((const void *)&b.num, 1, 0);
  gc_add_root((const void *)&b.denom, 1, 0);
  gc_obj left = vm_runtime_math_mul_slow(a.num, b.denom);
  gc_add_root((const void *)&left, 1, 0);
  gc_obj right = vm_runtime_math_mul_slow(b.num, a.denom);
  int cmp = numeric_exact_compare(left, right);
  gc_remove_root((const void *)&left, 0);
  gc_remove_root((const void *)&b.denom, 0);
  gc_remove_root((const void *)&b.num, 0);
  gc_remove_root((const void *)&a.denom, 0);
  gc_remove_root((const void *)&a.num, 0);
  return cmp;
}

static gc_obj compnum_add(gc_obj a, gc_obj b) {
  gc_obj ca_obj = get_compnum(a);
  gc_add_root((const void *)&ca_obj, 1, 0);
  gc_obj cb_obj = get_compnum(b);
  gc_add_root((const void *)&cb_obj, 1, 0);
  compnum_s *ca = to_compnum(ca_obj);
  compnum_s *cb = to_compnum(cb_obj);
  gc_obj real = vm_runtime_math_add_slow(ca->real, cb->real);
  gc_add_root((const void *)&real, 1, 0);
  gc_obj imag = vm_runtime_math_add_slow(ca->imag, cb->imag);
  gc_add_root((const void *)&imag, 1, 0);
  gc_obj out = SCM_MAKE_RECTANGULAR(real, imag);
  gc_remove_root((const void *)&imag, 0);
  gc_remove_root((const void *)&real, 0);
  gc_remove_root((const void *)&cb_obj, 0);
  gc_remove_root((const void *)&ca_obj, 0);
  return out;
}

static gc_obj compnum_sub(gc_obj a, gc_obj b) {
  gc_obj ca_obj = get_compnum(a);
  gc_add_root((const void *)&ca_obj, 1, 0);
  gc_obj cb_obj = get_compnum(b);
  gc_add_root((const void *)&cb_obj, 1, 0);
  compnum_s *ca = to_compnum(ca_obj);
  compnum_s *cb = to_compnum(cb_obj);
  gc_obj real = vm_runtime_math_sub_slow(ca->real, cb->real);
  gc_add_root((const void *)&real, 1, 0);
  gc_obj imag = vm_runtime_math_sub_slow(ca->imag, cb->imag);
  gc_add_root((const void *)&imag, 1, 0);
  gc_obj out = SCM_MAKE_RECTANGULAR(real, imag);
  gc_remove_root((const void *)&imag, 0);
  gc_remove_root((const void *)&real, 0);
  gc_remove_root((const void *)&cb_obj, 0);
  gc_remove_root((const void *)&ca_obj, 0);
  return out;
}

static gc_obj compnum_mul(gc_obj a, gc_obj b) {
  gc_obj ca_obj = get_compnum(a);
  gc_add_root((const void *)&ca_obj, 1, 0);
  gc_obj cb_obj = get_compnum(b);
  gc_add_root((const void *)&cb_obj, 1, 0);
  compnum_s *ca = to_compnum(ca_obj);
  compnum_s *cb = to_compnum(cb_obj);
  gc_obj ac = vm_runtime_math_mul_slow(ca->real, cb->real);
  gc_add_root((const void *)&ac, 1, 0);
  gc_obj bd = vm_runtime_math_mul_slow(ca->imag, cb->imag);
  gc_add_root((const void *)&bd, 1, 0);
  gc_obj ad = vm_runtime_math_mul_slow(ca->real, cb->imag);
  gc_add_root((const void *)&ad, 1, 0);
  gc_obj bc = vm_runtime_math_mul_slow(ca->imag, cb->real);
  gc_obj real = vm_runtime_math_sub_slow(ac, bd);
  gc_add_root((const void *)&real, 1, 0);
  gc_obj imag = vm_runtime_math_add_slow(ad, bc);
  gc_add_root((const void *)&imag, 1, 0);
  gc_obj out = SCM_MAKE_RECTANGULAR(real, imag);
  gc_remove_root((const void *)&imag, 0);
  gc_remove_root((const void *)&real, 0);
  gc_remove_root((const void *)&ad, 0);
  gc_remove_root((const void *)&bd, 0);
  gc_remove_root((const void *)&ac, 0);
  gc_remove_root((const void *)&cb_obj, 0);
  gc_remove_root((const void *)&ca_obj, 0);
  return out;
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

#define DEFINE_VM_RUNTIME_OVERFLOW_SLOW(name, oplcname, op, shift)             \
  gc_obj vm_runtime_math_##name##_slow(gc_obj v1, gc_obj v2) {                 \
    if (is_compnum(v1) || is_compnum(v2)) {                                    \
      return compnum_##oplcname(v1, v2);                                       \
    }                                                                          \
    if (is_flonum(v1) || is_flonum(v2)) {                                      \
      return root2_box_flonum(                                                 \
          &v1, &v2, op(numeric_to_double(v1), numeric_to_double(v2)));         \
    }                                                                          \
    if (is_ratnum(v1) || is_ratnum(v2)) {                                      \
      ratnum_s r1 = get_ratnum(v1);                                            \
      ratnum_s r2 = get_ratnum(v2);                                            \
      return tag_ratnum(ratnum_##oplcname(r1, r2));                            \
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
    gc_obj res = normalize_exact_integer(                                      \
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
  if (is_compnum(v1) || is_compnum(v2)) {
    abort();
  }
  if (numeric_is_zero(v2)) {
    abort();
  }
  if (is_flonum(v1) || is_flonum(v2)) {
    return root2_box_flonum(&v1, &v2,
                            numeric_to_double(v1) / numeric_to_double(v2));
  }
  ratnum_s r1 = get_ratnum(v1);
  ratnum_s r2 = get_ratnum(v2);
  return tag_ratnum(ratnum_div(r1, r2));
}

#define DEFINE_VM_RUNTIME_DIVMOD_SLOW(name, fixnum_body, flonum_body, field)   \
  gc_obj vm_runtime_math_##name##_slow(gc_obj v1, gc_obj v2) {                 \
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

DEFINE_VM_RUNTIME_DIVMOD_SLOW(quotient, to_fixnum(v1) / to_fixnum(v2),
                              trunc(numeric_to_double(v1) /
                                    numeric_to_double(v2)),
                              q)
DEFINE_VM_RUNTIME_DIVMOD_SLOW(mod, to_fixnum(v1) % to_fixnum(v2),
                              fmod(numeric_to_double(v1),
                                   numeric_to_double(v2)),
                              r)

#undef DEFINE_VM_RUNTIME_DIVMOD_SLOW

#define DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW(name, op)                           \
  gc_obj vm_runtime_cmp_##name##_slow(gc_obj v1, gc_obj v2) {                  \
    if (is_compnum(v1) || is_compnum(v2)) {                                    \
      abort();                                                                 \
    }                                                                          \
    if (is_flonum(v1) || is_flonum(v2)) {                                      \
      return (numeric_to_double(v1) op numeric_to_double(v2)) ? TRUE_REP       \
                                                              : FALSE_REP;     \
    }                                                                          \
    if (is_ratnum(v1) || is_ratnum(v2)) {                                      \
      ratnum_s r1 = get_ratnum(v1);                                            \
      ratnum_s r2 = get_ratnum(v2);                                            \
      return (ratnum_cmp(r1, r2) op 0) ? TRUE_REP : FALSE_REP;                 \
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
