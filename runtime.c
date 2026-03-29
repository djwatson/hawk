#include <assert.h>
#include <fcntl.h>
#include <limits.h>

#include "bigint.h"
#include "ftoa.h"
#include "gc.h"
#include "hawk.h"
#include "types.h"

#define FIXNUM_MAX_VALUE ((INT64_C(1) << (63 - FIXNUM_SHIFT)) - 1)
#define FIXNUM_MIN_VALUE (-(INT64_C(1) << (63 - FIXNUM_SHIFT)))

static bool fits_fixnum_i64(int64_t value) {
  return value >= FIXNUM_MIN_VALUE && value <= FIXNUM_MAX_VALUE;
}

static gc_obj normalize_exact_integer(gc_obj value) {
  if (!is_bignum(value)) {
    return value;
  }
  bn_i64_result_t i64 = bn_to_i64(to_bignum(value));
  if (i64.ok && fits_fixnum_i64(i64.value)) {
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
