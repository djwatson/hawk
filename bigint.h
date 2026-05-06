#ifndef BIGINT_H
#define BIGINT_H

#include <stdbool.h>
#include <stdint.h>

typedef struct bn {
  uintptr_t gc_hdr; /* GC-owned header word; must be first. */
  uint32_t alloc;   /* Allocated limb capacity. */
  uint32_t used;    /* In-use limbs, normalized to >= 1. */
  bool negative;    /* Sign bit. */
  uint64_t limb[];  /* Little-endian limbs (limb[0] = least-significant). */
} bn_t;

bn_t *bn_from_i64(int64_t value);
bn_t *bn_copy(const bn_t *a);

bool bn_is_zero(const bn_t *bn);
bool bn_is_negative(const bn_t *bn);
bool bn_is_odd(const bn_t *bn);

typedef struct bn_i64_result {
  bool ok;
  int64_t value;
} bn_i64_result_t;

/* Convert to int64_t when representable. */
bn_i64_result_t bn_to_i64(const bn_t *bn);

/* Signed comparison: return -1, 0, 1. */
int bn_cmp(const bn_t *a, const bn_t *b);

/* Public arithmetic API (signed). */
bn_t *bn_add(const bn_t *a, const bn_t *b);
bn_t *bn_sub(const bn_t *a, const bn_t *b);
bn_t *bn_mul(const bn_t *a, const bn_t *b);
bn_t *bn_div(const bn_t *a, const bn_t *b);

typedef struct bn_divmod_result {
  bn_t *q;
  bn_t *r;
} bn_divmod_result_t;

typedef struct bn_sqrt_result {
  bn_t *q;
  bn_t *r;
} bn_sqrt_result_t;

bn_divmod_result_t bn_divmod(const bn_t *a, const bn_t *b);
bn_sqrt_result_t bn_sqrt(const bn_t *a);
uint32_t bn_bit_length(const bn_t *a);
bn_t *bn_shr_bits(const bn_t *a, uint32_t bits);
bn_t *bn_shl_bits(const bn_t *a, uint32_t bits);

/* Supported radix values: 2, 8, 10, 16. Returns nullptr on invalid radix/OOM.
 */
char *bn_to_string(const bn_t *a, uint32_t radix);

#endif /* BIGINT_H */
