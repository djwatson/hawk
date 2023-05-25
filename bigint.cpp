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
    b = a;
    a = tmp;
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
  uint64_t i = 0;
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

#include <gmp.h>

int main() {
  uint64_t inputs[512];
  memset(inputs, 0, sizeof(inputs));

  size_t sz = fread(inputs, 1, 512 * sizeof(uint64_t), stdin);
  sz /= sizeof(uint64_t);
  
  auto a = big_alloc(1);
  big_set_from_fixnum(a, 0);
  

  mpz_t am;
  mpz_t bm;
  
  mpz_inits(am, bm, nullptr);
  mpz_set_ui(am, 0);
  
  for(uint64_t i =0; i < sz; i++) {
    auto in = inputs[i];
    auto b = big_alloc(1);
    big_set_from_fixnum(b, in);

    auto res = big_add_unsigned(a, b);
    free(a);
    free(b);
    a = res;

    mpz_set_ui(bm, in);
    mpz_add(am, am, bm);
  }
  char buf1[1024];
  big_print_hex(buf1, 1024, a);
  //  printf("%s\n", buf1);

  free(a);

  char buf2[1024];
  gmp_snprintf(buf2, 1024, "%Zx", am);
  //  printf("%s\n", buf2);
  assert(strcmp(buf2, buf1) == 0);

  mpz_clears(am, bm, nullptr);
  return 0;
}
