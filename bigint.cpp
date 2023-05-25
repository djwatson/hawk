#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct bignum {
  long type;
  uint64_t len;
  uint64_t used;
  uint64_t sign;
  uint64_t l[];
};

bignum* big_alloc(size_t len) {
  auto res = (bignum*)malloc(sizeof(bignum) + len*sizeof(long));
  res->type = 0;
  res->len = len;
  res->used = 0;
  return res;
}

void big_set_from_fixnum(bignum*a, uint64_t fix) {
  assert(a->len >= 1);
  a->used = 1;
  a->l[0] = fix;
}

void big_print_hex(char* buf, size_t buflen, bignum* a) {
  size_t pos = 0;
  for(uint64_t i = a->used; i > 0; i--) {
    sprintf(&buf[pos], "%016lx",  a->l[i-1]);
    pos += 16;
  }
  buf[pos] = '\0';
  auto npos = 0;
  while(buf[npos] == '0' && npos < pos) npos++;
  if (npos) memmove(buf, &buf[npos], buflen - npos);
  if (buf[0] == '\0') {
    buf[0] = '0';
    buf[1] = '\0';
  }
}

bignum* big_add_unsigned(bignum* a, bignum* b) {
  // Make a is bigger.
  if (a->used < b->used) {
    bignum* tmp = a;
    a = b;
    b = tmp;
  }
  auto nlen = a->used + 1;
  int carry = 0;
  auto res = big_alloc(nlen);

  // Copy a in to res.
  memcpy(res->l, a->l, sizeof(uint64_t)*a->used);
  res->l[nlen-1] = 0;
  res->used = nlen;

  uint64_t* bp = b->l;
  uint64_t* bp_end = b->l + b->used;
  uint64_t* rp = res->l;

  // Scan over b, adding it to res.
  uint64_t sum;
  while(bp < bp_end) {
    uint64_t cur = (*rp);
    if (carry) {
      sum = cur + *bp + 1;
      carry = sum <= cur;
    } else {
      sum = cur + *bp;
      carry = sum < cur;
    }
    bp++;
    (*rp++) = sum;
  }
  // Finish any carry.
  while (carry) {
    sum = (*rp) + 1;
    carry = (sum == 0);
    (*rp++) = sum;
  }
  if (res->l[nlen-1] == 0) {
    res->used--;
  }

  // simplify.
  return res;
}

void big_simplify(bignum* a) {
  while(a->used > 0 && a->l[a->used-1] == 0) {
      a->used--;
  }
}

bignum* big_sub_unsigned(bignum* a, bignum* b) {
  // a *MUST* be bigger.
  assert(a->used >= b->used);
  //assert(bigint_cmp(a, b) == 1);
  auto nlen = a->used;
  int borrow = 0;
  auto res = big_alloc(nlen);

  // Copy a in to res.
  memcpy(res->l, a->l, sizeof(uint64_t)*a->used);
  res->used = nlen;

  uint64_t* bp = b->l;
  uint64_t* bp_end = b->l + b->used;
  uint64_t* rp = res->l;

  // Scan over b, adding it to res.
  uint64_t diff;
  while(bp < bp_end) {
    uint64_t cur = (*rp);
    if (borrow) {
      diff = cur - *bp - 1;
      borrow = diff >= cur;
    } else {
      diff = cur - *bp;
      borrow = diff > cur;
    }
    bp++;
    (*rp++) = diff;
  }
  // Finish any borrow.
  while (borrow) {
    uint64_t cur = (*rp);
    diff = cur - borrow;
    borrow = diff >= cur;
    (*rp++) = diff;
  }

  // simplify.
  big_simplify(res);
  return res;
}

bignum* big_mul_unsigned(bignum* a, bignum* b) {
  // Make a smaller.
  if (a->used > b->used) {
    bignum* tmp = a;
    a = b;
    b = tmp;
  }
  assert(a->used <= b->used);

  
  auto nlen = a->used + b->used;
  auto res = big_alloc(nlen);
  memset(res->l, 0, sizeof(uint64_t)*nlen);
  res->used = nlen; // Fixed by simplify.

  for(uint64_t i = 0; i < b->used; i++) {
    uint64_t carry = 0;
    __uint128_t yval = b->l[i];
    for(uint64_t j = 0; j < a->used; j++) {
      __uint128_t prod = __uint128_t(a->l[j]) * yval + res->l[i + j] + carry;
      res->l[i + j] = prod;
      carry = prod>>64;
    }
    res->l[i + a->used] = carry;
  }

  big_simplify(res);
  return res;
}

#include <gmp.h>

int main() {
  uint64_t inputs[512];
  memset(inputs, 0, sizeof(inputs));

  size_t sz = fread(inputs, 1, 512 * sizeof(uint64_t), stdin);
  sz /= sizeof(uint64_t);
  
  auto a = big_alloc(1);
  big_set_from_fixnum(a, 1);

  mpz_t am;
  mpz_t bm;
  
  mpz_inits(am, bm, nullptr);
  mpz_set_ui(am, 1);
  
  for(uint64_t i =0; i < sz; i++) {
    auto in = inputs[i];
    auto b = big_alloc(1);
    
    big_set_from_fixnum(b, in);
    mpz_set_ui(bm, in);

    bignum*res;
    res = big_mul_unsigned(a, b);
    mpz_mul(am, am, bm);
    free(a);
    free(b);
    a = res;

  }
  char buf1[1024];
  big_print_hex(buf1, 1024, a);
   printf("%s\n", buf1);

  free(a);

  char buf2[1024];
  gmp_snprintf(buf2, 1024, "%Zx", am);
   printf("%s\n", buf2);
  assert(strcmp(buf2, buf1) == 0);

  mpz_clears(am, bm, nullptr);
  return 0;
}
