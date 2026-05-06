#include "bigint.h"
#include "gc.h"
#include "types.h"

#include <assert.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

// NOLINTBEGIN(clang-analyzer-deadcode.DeadStores)

#define BN_ALLOC(sz) gc_alloc((uint64_t)(((sz) + 7) & ~((size_t)7)))
#define BN_FREE(ptr) ((void)(ptr))
#define BN_ROOT(slot) gc_add_root((const void *)(slot), 1, PTR_TAG)
#define BN_UNROOT(slot) gc_remove_root((const void *)(slot), PTR_TAG)

typedef struct bn_root_guard {
  bn_t **slot;
} bn_root_guard_t;

static size_t bn_size_for_limbs(uint32_t alloc) {
  return sizeof(bn_t) + ((size_t)alloc * sizeof(uint64_t));
}

static bn_root_guard_t bn_root_slot(bn_t **slot) {
  bn_root_guard_t g = {.slot = nullptr};
  BN_ROOT(slot);
  g.slot = slot;
  return g;
}

static void bn_root_guard_cleanup(bn_root_guard_t *g) { BN_UNROOT(g->slot); }

static bn_t *bn_new(uint32_t alloc) {
  assert(alloc >= 1);
  bn_t *bn = (bn_t *)BN_ALLOC(bn_size_for_limbs(alloc));
  bn->gc_hdr = BIGNUM_TAG;
  bn->alloc = alloc;
  bn->used = 1;
  bn->negative = false;
  bn->limb[0] = 0;
  return bn;
}

bn_t *bn_from_i64(int64_t value) {
  bn_t *bn = bn_new(1);
  bn->used = 1;
  if (value < 0) {
    bn->negative = true;
    if (value == INT64_MIN) {
      bn->limb[0] = (1ULL << 63);
    } else {
      bn->limb[0] = (uint64_t)(-value);
    }
  } else {
    bn->limb[0] = (uint64_t)value;
    bn->negative = false;
  }
  if (bn->limb[0] == 0) {
    bn->negative = false;
  }
  return bn;
}

bn_t *bn_copy(const bn_t *a) {
  bn_root_guard_t rg_a __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&a);
  assert(a != nullptr);
  bn_t *res = bn_new(a->used);
  res->used = a->used;
  res->negative = a->negative;
  memcpy(res->limb, a->limb, (size_t)a->used * sizeof(uint64_t));
  return res;
}

bool bn_is_zero(const bn_t *bn) {
  assert(bn != nullptr);
  assert(bn->used <= bn->alloc);
  assert(bn->used >= 1);
  return (bn->used == 1) && (bn->limb[0] == 0);
}

bool bn_is_negative(const bn_t *bn) {
  assert(bn != nullptr);
  return bn->negative;
}

bool bn_is_odd(const bn_t *bn) {
  assert(bn != nullptr);
  assert(bn->used >= 1);
  return (bn->limb[0] & 1U) != 0;
}

static void bn_normalize(bn_t *bn) {
  assert(bn != nullptr);
  assert(bn->used <= bn->alloc);
  if (bn->used == 0) {
    bn->used = 1;
  }
  while (bn->used > 1 && bn->limb[bn->used - 1] == 0) {
    bn->used--;
  }
  if (bn_is_zero(bn)) {
    bn->negative = false;
  }
}

bn_i64_result_t bn_to_i64(const bn_t *bn) {
  bn_i64_result_t out = {.ok = false, .value = 0};
  assert(bn != nullptr);
  assert(bn->used >= 1);

  bool neg = bn_is_negative(bn);
  uint64_t mag = bn->limb[0];
  for (uint32_t i = 1; i < bn->used; i++) {
    if (bn->limb[i] != 0) {
      return out;
    }
  }

  if (!neg) {
    if (mag > (uint64_t)INT64_MAX) {
      return out;
    }
    out.ok = true;
    out.value = (int64_t)mag;
    return out;
  }

  if (mag > (1ULL << 63)) {
    return out;
  }
  out.ok = true;
  if (mag == (1ULL << 63)) {
    out.value = INT64_MIN;
  } else {
    out.value = -(int64_t)mag;
  }
  return out;
}

static int bn_cmp_unsigned(const bn_t *a, const bn_t *b) {
  assert(a != nullptr);
  assert(b != nullptr);
  assert(a->used >= 1);
  assert(b->used >= 1);

  if (a->used > b->used) {
    return 1;
  }
  if (a->used < b->used) {
    return -1;
  }
  for (uint32_t i = a->used; i > 0; i--) {
    uint64_t av = a->limb[i - 1];
    uint64_t bv = b->limb[i - 1];
    if (av > bv) {
      return 1;
    }
    if (av < bv) {
      return -1;
    }
  }
  return 0;
}

int bn_cmp(const bn_t *a, const bn_t *b) {
  bool aneg = bn_is_negative(a);
  bool bneg = bn_is_negative(b);
  if (aneg && !bneg) {
    return -1;
  }
  if (!aneg && bneg) {
    return 1;
  }
  if (aneg) {
    return bn_cmp_unsigned(b, a);
  }
  return bn_cmp_unsigned(a, b);
}

static bn_t *bn_add_unsigned(const bn_t *a, const bn_t *b) {
  bn_root_guard_t rg_a __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&a);
  bn_root_guard_t rg_b __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&b);
  assert(a != nullptr);
  assert(b != nullptr);
  uint32_t a_used = a->used;
  uint32_t b_used = b->used;
  uint32_t min_used = (a_used < b_used) ? a_used : b_used;
  uint32_t max_used = (a_used > b_used) ? a_used : b_used;
  bn_t *res = bn_new(max_used + 1);

  const uint64_t *ap = a->limb;
  const uint64_t *bp = b->limb;
  uint64_t *rp = res->limb;

  unsigned char carry = 0;
  uint32_t i = 0;
  for (; i < min_used; i++) {
    unsigned long long carry_out = 0;
    rp[i] = (uint64_t)__builtin_addcll((unsigned long long)ap[i],
                                       (unsigned long long)bp[i],
                                       (unsigned long long)carry, &carry_out);
    carry = (unsigned char)carry_out;
  }

  const uint64_t *tail = (a_used > b_used) ? ap : bp;
  for (; i < max_used; i++) {
    unsigned long long carry_out = 0;
    rp[i] = (uint64_t)__builtin_addcll((unsigned long long)tail[i], 0,
                                       (unsigned long long)carry, &carry_out);
    carry = (unsigned char)carry_out;
  }

  rp[max_used] = (uint64_t)(carry != 0);
  res->used = max_used + (carry != 0);
  return res;
}

static uint32_t bn_trim_limb_len(const uint64_t *a, uint32_t n) {
  while (n > 0 && a[n - 1] == 0) {
    n--;
  }
  return n;
}

static bn_t *bn_sub_unsigned(const bn_t *a, const bn_t *b) {
  bn_root_guard_t rg_a __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&a);
  bn_root_guard_t rg_b __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&b);
  assert(a != nullptr);
  assert(b != nullptr);
  assert(bn_cmp_unsigned(a, b) >= 0);

  uint32_t a_used = a->used;
  uint32_t b_used = b->used;
  bn_t *res = bn_new(a->used);
  res->used = a_used;

  unsigned long long borrow = 0;
  uint32_t i = 0;
  for (; i < b_used; i++) {
    unsigned long long av = a->limb[i];
    unsigned long long bv = b->limb[i];
    unsigned long long borrow1 = 0;
    unsigned long long t1 = __builtin_subcll(av, bv, 0, &borrow1);
    unsigned long long borrow2 = 0;
    unsigned long long t2 = __builtin_subcll(t1, 0, borrow, &borrow2);
    res->limb[i] = (uint64_t)t2;
    borrow = borrow1 | borrow2;
  }
  if (i < a_used) {
    for (; i < a_used; i++) {
      unsigned long long borrow_next = 0;
      unsigned long long t = __builtin_subcll((unsigned long long)a->limb[i], 0,
                                              borrow, &borrow_next);
      res->limb[i] = (uint64_t)t;
      borrow = borrow_next;
    }
  }
  assert(borrow == 0);
  uint32_t used = bn_trim_limb_len(res->limb, res->used);
  res->used = (used == 0) ? 1 : used;
  return res;
}

static void bn_mul_schoolbook_limbs(uint64_t *out, const uint64_t *a,
                                    uint32_t an, const uint64_t *b,
                                    uint32_t bn) {
  if (an == 0 || bn == 0) {
    return;
  }

  /* Reduce outer-loop overhead: iterate outer over the shorter operand. */
  if (an > bn) {
    const uint64_t *t = a;
    a = b;
    b = t;
    uint32_t tn = an;
    an = bn;
    bn = tn;
  }

  /* Row 0: no reads from out, so no pre-zero memset required. */
  {
    const uint64_t ai = a[0];
    __uint128_t carry = 0;
    for (uint32_t j = 0; j < bn; j++) {
      __uint128_t sum = ((__uint128_t)ai * (__uint128_t)b[j]) + carry;
      out[j] = (uint64_t)sum;
      carry = sum >> 64;
    }
    out[bn] = (uint64_t)carry;
  }

  /* Remaining rows: read only cells written by prior rows. */
  for (uint32_t i = 1; i < an; i++) {
    const uint64_t ai = a[i];
    const uint64_t *bp = b;
    uint64_t *op = out + i;
    __uint128_t carry = 0;
    for (uint32_t j = 0; j < bn; j++) {
      __uint128_t cur = (__uint128_t)op[j];
      __uint128_t prod = (__uint128_t)ai * (__uint128_t)bp[j];
      __uint128_t sum = cur + prod + carry;
      op[j] = (uint64_t)sum;
      carry = sum >> 64;
    }
    op[bn] = (uint64_t)carry;
  }
}

static bn_t *bn_clone_unsigned(const bn_t *a) {
  bn_root_guard_t rg_a __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&a);
  bn_t *res = bn_new(a->used);
  res->used = a->used;
  memcpy(res->limb, a->limb, (size_t)a->used * sizeof(uint64_t));
  return res;
}

static bn_t *bn_mul_unsigned(const bn_t *a, const bn_t *b) {
  bn_root_guard_t rg_a __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&a);
  bn_root_guard_t rg_b __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&b);
  assert(a != nullptr);
  assert(b != nullptr);
  uint32_t an = bn_trim_limb_len(a->limb, a->used);
  uint32_t bn = bn_trim_limb_len(b->limb, b->used);
  if (an == 0 || bn == 0) {
    bn_t *z = bn_new(1);
    z->used = 1;
    z->limb[0] = 0;
    return z;
  }

  uint32_t outn = an + bn;
  bn_t *res = bn_new(outn);
  res->used = outn;
  bn_mul_schoolbook_limbs(res->limb, a->limb, an, b->limb, bn);
  uint32_t used = bn_trim_limb_len(res->limb, outn);
  res->used = (used == 0) ? 1 : used;
  return res;
}

static bn_divmod_result_t bn_divmod_knuth_unsigned(const bn_t *num,
                                                   const bn_t *denom);
static uint32_t bn_bit_length_unsigned(const bn_t *a);

static bn_t *bn_zero_unsigned(void) { return bn_new(1); }

static bn_t *bn_low_bits_unsigned(const bn_t *a, uint32_t bits) {
  bn_root_guard_t rg_a __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&a);
  if (bits == 0) {
    return bn_zero_unsigned();
  }

  uint32_t bit_len = bn_bit_length_unsigned(a);
  if (bits >= bit_len) {
    return bn_clone_unsigned(a);
  }

  uint32_t words = bits / 64U;
  uint32_t off = bits % 64U;
  uint32_t new_used = words + (off != 0);
  if (new_used == 0) {
    return bn_zero_unsigned();
  }

  bn_t *res = bn_new(new_used);
  res->used = new_used;
  if (words != 0) {
    memcpy(res->limb, a->limb, (size_t)words * sizeof(uint64_t));
  }
  if (off != 0) {
    res->limb[words] = a->limb[words] & ((UINT64_C(1) << off) - 1);
  }
  bn_normalize(res);
  return res;
}

static uint32_t bn_word_length_unsigned(const bn_t *a) {
  uint32_t used = a->used;
  while (used > 1 && a->limb[used - 1] == 0) {
    used--;
  }
  return used;
}

static uint32_t bn_bit_length_unsigned(const bn_t *a) {
  uint32_t used = bn_word_length_unsigned(a);
  if (used == 1 && a->limb[0] == 0) {
    return 0;
  }
  uint64_t top = a->limb[used - 1];
  uint32_t top_bits = 64U - (uint32_t)__builtin_clzll(top);
  return ((used - 1) * 64U) + top_bits;
}

static bn_t *bn_shr_bits_unsigned(const bn_t *a, uint32_t bits) {
  bn_root_guard_t rg_a __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&a);
  if (bits == 0) {
    return bn_clone_unsigned(a);
  }
  uint32_t word = bits / 64U;
  uint32_t off = bits % 64U;
  if (word >= a->used) {
    return bn_zero_unsigned();
  }
  uint32_t new_used = a->used - word;
  bn_t *res = bn_new(new_used);
  res->used = new_used;
  for (uint32_t i = 0; i < new_used; i++) {
    uint64_t low = a->limb[i + word];
    uint64_t high = (i + word + 1 < a->used) ? a->limb[i + word + 1] : 0;
    res->limb[i] = (off == 0) ? low : ((low >> off) | (high << (64U - off)));
  }
  bn_normalize(res);
  return res;
}

static bn_t *bn_shl_bits_unsigned(const bn_t *a, uint32_t bits) {
  bn_root_guard_t rg_a __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&a);
  if (bits == 0) {
    return bn_clone_unsigned(a);
  }
  if (bn_is_zero(a)) {
    return bn_zero_unsigned();
  }

  uint32_t word = bits / 64U;
  uint32_t off = bits % 64U;

  if (off == 0) {
    uint32_t new_used = a->used + word;
    bn_t *res = bn_new(new_used);
    res->used = new_used;
    if (word != 0) {
      memset(res->limb, 0, (size_t)word * sizeof(uint64_t));
    }
    memcpy(res->limb + word, a->limb, (size_t)a->used * sizeof(uint64_t));
    return res;
  }

  uint32_t new_used = a->used + word + 1U;
  bn_t *res = bn_new(new_used);
  if (word != 0) {
    memset(res->limb, 0, (size_t)word * sizeof(uint64_t));
  }

  uint64_t carry = 0;
  for (uint32_t i = 0; i < a->used; i++) {
    uint32_t d = i + word;
    uint64_t v = a->limb[i];
    res->limb[d] = (v << off) | carry;
    carry = v >> (64U - off);
  }
  res->limb[word + a->used] = carry;
  res->used = word + a->used + (carry != 0);
  return res;
}

/* Compute up[0..n] -= vp[0..n-1] * qdigit, return final borrow (0/1). */
static unsigned long long bn_submul_1_u64(uint64_t *up, const uint64_t *vp,
                                          int n, uint64_t qdigit) {
  unsigned long long mul_carry = 0;
  unsigned long long sub_borrow = 0;
  int i = 0;

  for (; i < n; i++) {
    __uint128_t prod = ((__uint128_t)qdigit * (__uint128_t)vp[i]) + mul_carry;
    unsigned long long lo = (unsigned long long)prod;
    mul_carry = (unsigned long long)(prod >> 64);
    up[i] = (uint64_t)__builtin_subcll((unsigned long long)up[i], lo,
                                       sub_borrow, &sub_borrow);
  }

  unsigned long long borrow_out = 0;
  up[n] = (uint64_t)__builtin_subcll((unsigned long long)up[n], mul_carry,
                                     sub_borrow, &borrow_out);
  return borrow_out;
}

static void bn_add_n_u64(uint64_t *up, const uint64_t *vp, int n) {
  unsigned long long add_carry = 0;
  int i = 0;
  for (; i < n; i++) {
    up[i] = (uint64_t)__builtin_addcll((unsigned long long)up[i],
                                       (unsigned long long)vp[i], add_carry,
                                       &add_carry);
  }
  up[n] = (uint64_t)__builtin_addcll((unsigned long long)up[n], 0, add_carry,
                                     &add_carry);
}

static int divmnu128(uint64_t q[], uint64_t r[], const uint64_t u[],
                     const uint64_t v[], int m, int n) {
  if (m < n || n <= 0 || v[n - 1] == 0) {
    return 1;
  }

  int s = __builtin_clzll(v[n - 1]); /* 0 <= s <= 63 */
  uint64_t *vn = (uint64_t *)malloc((size_t)n * sizeof(uint64_t));
  uint64_t *un = (uint64_t *)malloc((size_t)(m + 1) * sizeof(uint64_t));
  assert(vn);
  assert(un);

  if (s == 0) {
    for (int i = 0; i < n; i++) {
      vn[i] = v[i];
    }
    for (int i = 0; i < m; i++) {
      un[i] = u[i];
    }
    un[m] = 0;
  } else {
    for (int i = n - 1; i > 0; i--) {
      vn[i] = (v[i] << s) | ((uint64_t)((__uint128_t)v[i - 1] >> (64 - s)));
    }
    vn[0] = v[0] << s;

    un[m] = (uint64_t)((__uint128_t)u[m - 1] >> (64 - s));
    for (int i = m - 1; i > 0; i--) {
      un[i] = (u[i] << s) | ((uint64_t)((__uint128_t)u[i - 1] >> (64 - s)));
    }
    un[0] = u[0] << s;
  }

  for (int j = m - n; j >= 0; j--) {
    __uint128_t u2 = ((__uint128_t)un[j + n] << 64) + un[j + n - 1];
    __uint128_t qhat = u2 / vn[n - 1];
    __uint128_t rhat = u2 % vn[n - 1];
  again:
    if ((qhat >> 64) != 0 ||
        (n > 1 && ((uint64_t)qhat * (__uint128_t)vn[n - 2]) >
                      ((rhat << 64) + un[j + n - 2]))) {
      qhat = qhat - 1;
      rhat = rhat + vn[n - 1];
      if (n > 1 && (rhat >> 64) == 0) {
        goto again;
      }
    }

    uint64_t qdigit = (uint64_t)qhat;
    uint64_t *up = un + j;
    unsigned long long borrow_out = bn_submul_1_u64(up, vn, n, qdigit);
    q[j] = (uint64_t)qhat;
    if (borrow_out) {
      q[j] = q[j] - 1;
      bn_add_n_u64(up, vn, n);
    }
  }

  if (r != nullptr) {
    if (s == 0) {
      for (int i = 0; i < n; i++) {
        r[i] = un[i];
      }
    } else {
      for (int i = 0; i < n - 1; i++) {
        r[i] = (un[i] >> s) | ((uint64_t)((__uint128_t)un[i + 1] << (64 - s)));
      }
      r[n - 1] = un[n - 1] >> s;
    }
  }

  free(vn);
  free(un);
  return 0;
}

static bn_divmod_result_t bn_divmod_knuth_unsigned(const bn_t *num,
                                                   const bn_t *denom) {
  bn_root_guard_t rg_num __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&num);
  bn_root_guard_t rg_denom __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&denom);
  bn_divmod_result_t out = {.q = nullptr, .r = nullptr};
  assert(num != nullptr);
  assert(denom != nullptr);
  assert(!bn_is_zero(denom));

  int cmp = bn_cmp_unsigned(num, denom);
  bn_t *q = nullptr;
  bn_t *r = nullptr;
  bn_root_guard_t q_num __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&q);

  if (cmp < 0) {
    q = bn_new(1);
    r = bn_clone_unsigned(num);
    out.q = q;
    out.r = r;
    return out;
  }
  if (cmp == 0) {
    q = bn_new(1);
    r = bn_new(1);
    q->limb[0] = 1;
    q->used = 1;
    out.q = q;
    out.r = r;
    return out;
  }

  assert(num->used <= INT_MAX);
  assert(denom->used <= INT_MAX);

  q = bn_new(num->used);
  r = bn_new(denom->used);
  q->used = num->used - denom->used + 1;
  r->used = denom->used;
  int rc = divmnu128(q->limb, r->limb, num->limb, denom->limb, (int)num->used,
                     (int)denom->used);
  (void)rc;
  assert(rc == 0);
  bn_normalize(q);
  bn_normalize(r);
  out.q = q;
  out.r = r;
  return out;
}

static bool limbs_is_zero(const uint64_t *limb, uint32_t used) {
  return used == 1 && limb[0] == 0;
}

static uint32_t limbs_divmod_small(uint64_t *limb, uint32_t *used,
                                   uint32_t base) {
  __uint128_t rem = 0;
  for (uint32_t i = *used; i > 0; i--) {
    __uint128_t cur = (rem << 64) | limb[i - 1];
    limb[i - 1] = (uint64_t)(cur / base);
    rem = cur % base;
  }
  while (*used > 1 && limb[*used - 1] == 0) {
    (*used)--;
  }
  return (uint32_t)rem;
}

static bn_sqrt_result_t bn_sqrt_u64(uint64_t n) {
  bn_sqrt_result_t out = {.q = nullptr, .r = nullptr};
  uint64_t q = (uint64_t)sqrt((double)n);
  while ((__uint128_t)(q + 1) * (__uint128_t)(q + 1) <= n) {
    q++;
  }
  while ((__uint128_t)q * (__uint128_t)q > n) {
    q--;
  }

  bn_t *q_bn = bn_from_i64((int64_t)q);
  bn_root_guard_t rg_q __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&q_bn);
  bn_t *r_bn = bn_from_i64((int64_t)(n - ((__uint128_t)q * (__uint128_t)q)));
  out.q = q_bn;
  out.r = r_bn;
  return out;
}

static bn_sqrt_result_t bn_sqrt_unsigned(const bn_t *a) {
  bn_root_guard_t rg_a __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot((bn_t **)&a);
  bn_sqrt_result_t out = {.q = nullptr, .r = nullptr};

  if (bn_is_zero(a)) {
    bn_t *q = bn_new(1);
    bn_root_guard_t rg_q __attribute__((cleanup(bn_root_guard_cleanup))) =
        bn_root_slot(&q);
    bn_t *r = bn_new(1);
    out.q = q;
    out.r = r;
    return out;
  }

  if (bn_bit_length_unsigned(a) <= 64U) {
    return bn_sqrt_u64(a->limb[0]);
  }

  uint32_t b = (bn_bit_length_unsigned(a) + 1U) / 4U;

  bn_t *hi = bn_shr_bits_unsigned(a, b + b);
  bn_root_guard_t rg_hi __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&hi);
  bn_sqrt_result_t hi_qr = bn_sqrt_unsigned(hi);
  bn_t *s0 = hi_qr.q;
  bn_root_guard_t rg_s0 __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&s0);
  bn_t *r0 = hi_qr.r;
  bn_root_guard_t rg_r0 __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&r0);

  bn_t *r0_shift = bn_shl_bits_unsigned(r0, b);
  bn_root_guard_t rg_r0_shift __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&r0_shift);
  bn_t *mid = bn_shr_bits_unsigned(a, b);
  bn_root_guard_t rg_mid __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&mid);
  bn_t *mid_bits = bn_low_bits_unsigned(mid, b);
  bn_root_guard_t rg_mid_bits __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&mid_bits);
  bn_t *num = bn_add_unsigned(r0_shift, mid_bits);
  bn_root_guard_t rg_num __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&num);
  bn_t *den = bn_shl_bits_unsigned(s0, 1);
  bn_root_guard_t rg_den __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&den);

  bn_divmod_result_t qu = bn_divmod_knuth_unsigned(num, den);
  bn_t *q = qu.q;
  bn_root_guard_t rg_q __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&q);
  bn_t *u = qu.r;
  bn_root_guard_t rg_u __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&u);

  bn_t *s0_shift = bn_shl_bits_unsigned(s0, b);
  bn_root_guard_t rg_s0_shift __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&s0_shift);
  bn_t *s = bn_add_unsigned(s0_shift, q);
  bn_root_guard_t rg_s __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&s);
  bn_t *u_shift = bn_shl_bits_unsigned(u, b);
  bn_root_guard_t rg_u_shift __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&u_shift);
  bn_t *lo = bn_low_bits_unsigned(a, b);
  bn_root_guard_t rg_lo __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&lo);
  bn_t *lhs = bn_add_unsigned(u_shift, lo);
  bn_root_guard_t rg_lhs __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&lhs);
  bn_t *qq = bn_mul_unsigned(q, q);
  bn_root_guard_t rg_qq __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&qq);
  bn_t *r = bn_sub(lhs, qq);
  bn_root_guard_t rg_r __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&r);

  if (!bn_is_negative(r)) {
    out.q = s;
    out.r = r;
    return out;
  }

  bn_t *one = bn_from_i64(1);
  bn_root_guard_t rg_one __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&one);
  bn_t *q_adj = bn_sub_unsigned(s, one);
  bn_root_guard_t rg_q_adj __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&q_adj);
  bn_t *twice_s = bn_shl_bits_unsigned(s, 1);
  bn_root_guard_t rg_twice_s __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&twice_s);
  bn_t *corr = bn_sub_unsigned(twice_s, one);
  bn_root_guard_t rg_corr __attribute__((cleanup(bn_root_guard_cleanup))) =
      bn_root_slot(&corr);
  bn_t *r_adj = bn_add(r, corr);
  out.q = q_adj;
  out.r = r_adj;
  return out;
}

bn_t *bn_add(const bn_t *a, const bn_t *b) {
  assert(a != nullptr);
  assert(b != nullptr);

  bool aneg = bn_is_negative(a);
  bool bneg = bn_is_negative(b);

  if (aneg == bneg) {
    bn_t *res = bn_add_unsigned(a, b);
    if (aneg && !bn_is_zero(res)) {
      res->negative = true;
    }
    return res;
  }

  int cmp = bn_cmp_unsigned(a, b);
  if (cmp == 0) {
    return bn_new(1);
  }
  if (cmp > 0) {
    bn_t *res = bn_sub_unsigned(a, b);
    if (aneg && !bn_is_zero(res)) {
      res->negative = true;
    }
    return res;
  }

  bn_t *res = bn_sub_unsigned(b, a);
  if (bneg && !bn_is_zero(res)) {
    res->negative = true;
  }
  return res;
}

bn_t *bn_sub(const bn_t *a, const bn_t *b) {
  assert(a != nullptr);
  assert(b != nullptr);

  bool aneg = bn_is_negative(a);
  bool bneg = bn_is_negative(b);

  if (aneg != bneg) {
    bn_t *res = bn_add_unsigned(a, b);
    if (aneg && !bn_is_zero(res)) {
      res->negative = true;
    }
    return res;
  }

  int cmp = bn_cmp_unsigned(a, b);
  if (cmp == 0) {
    return bn_new(1);
  }
  if (cmp > 0) {
    bn_t *res = bn_sub_unsigned(a, b);
    if (aneg && !bn_is_zero(res)) {
      res->negative = true;
    }
    return res;
  }

  bn_t *res = bn_sub_unsigned(b, a);
  if (!aneg && !bn_is_zero(res)) {
    res->negative = true;
  }
  return res;
}

bn_t *bn_mul(const bn_t *a, const bn_t *b) {
  assert(a != nullptr);
  assert(b != nullptr);

  bn_t *res = bn_mul_unsigned(a, b);
  if ((bn_is_negative(a) ^ bn_is_negative(b)) && !bn_is_zero(res)) {
    res->negative = true;
  }
  return res;
}

static bn_divmod_result_t bn_divmod_impl(const bn_t *a, const bn_t *b) {
  assert(a != nullptr);
  assert(b != nullptr);
  assert(!bn_is_zero(b));

  bool q_neg = bn_is_negative(a) ^ bn_is_negative(b);
  bool r_neg = bn_is_negative(a);
  bn_divmod_result_t out = bn_divmod_knuth_unsigned(a, b);
  if (q_neg && !bn_is_zero(out.q)) {
    out.q->negative = true;
  }
  if (r_neg && !bn_is_zero(out.r)) {
    out.r->negative = true;
  }
  return out;
}

bn_t *bn_div(const bn_t *a, const bn_t *b) {
  assert(a != nullptr);
  assert(b != nullptr);
  assert(!bn_is_zero(b));

  bn_divmod_result_t qr = bn_divmod_impl(a, b);
  BN_FREE(qr.r);
  return qr.q;
}

uint32_t bn_bit_length(const bn_t *a) {
  assert(a != nullptr);
  return bn_bit_length_unsigned(a);
}

bn_t *bn_shr_bits(const bn_t *a, uint32_t bits) {
  assert(a != nullptr);
  bool neg = bn_is_negative(a);
  bn_t *res = bn_shr_bits_unsigned(a, bits);
  if (neg && !bn_is_zero(res)) {
    res->negative = true;
  }
  return res;
}

bn_t *bn_shl_bits(const bn_t *a, uint32_t bits) {
  assert(a != nullptr);
  bool neg = bn_is_negative(a);
  bn_t *res = bn_shl_bits_unsigned(a, bits);
  if (neg && !bn_is_zero(res)) {
    res->negative = true;
  }
  return res;
}

char *bn_to_string(const bn_t *a, uint32_t radix) {
  static const char digits[] = "0123456789abcdef";
  assert(a != nullptr);

  if (!(radix == 2 || radix == 8 || radix == 10 || radix == 16)) {
    return nullptr;
  }

  if (bn_is_zero(a)) {
    char *s = (char *)malloc(2);
    s[0] = '0';
    s[1] = '\0';
    return s;
  }

  uint32_t used = a->used;
  uint64_t *tmp = (uint64_t *)malloc((size_t)used * sizeof(uint64_t));
  memcpy(tmp, a->limb, (size_t)used * sizeof(uint64_t));
  while (used > 1 && tmp[used - 1] == 0) {
    used--;
  }

  size_t max_digits;
  if (radix == 2) {
    max_digits = (size_t)used * 64;
  } else if (radix == 8) {
    max_digits = ((size_t)used * 64 + 2) / 3;
  } else if (radix == 16) {
    max_digits = ((size_t)used * 64 + 3) / 4;
  } else {
    max_digits = (size_t)used * 20;
  }

  char *out = (char *)malloc(max_digits + 2);

  size_t pos = 0;
  while (!limbs_is_zero(tmp, used)) {
    uint32_t rem = limbs_divmod_small(tmp, &used, radix);
    out[pos++] = digits[rem];
  }
  if (bn_is_negative(a)) {
    out[pos++] = '-';
  }
  for (size_t i = 0; i < pos / 2; i++) {
    char c = out[i];
    out[i] = out[pos - 1 - i];
    out[pos - 1 - i] = c;
  }
  out[pos] = '\0';

  free(tmp);
  return out;
}

bn_divmod_result_t bn_divmod(const bn_t *a, const bn_t *b) {
  bn_divmod_result_t tmp = bn_divmod_impl(a, b);
  return tmp;
}

bn_sqrt_result_t bn_sqrt(const bn_t *a) {
  assert(a != nullptr);
  assert(!bn_is_negative(a));
  return bn_sqrt_unsigned(a);
}

// NOLINTEND(clang-analyzer-deadcode.DeadStores)
