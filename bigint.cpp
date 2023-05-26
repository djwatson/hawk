#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <gc/gc.h>

struct bignum {
  long type;
  uint64_t len;
  uint64_t used;
  uint64_t sign;
  uint64_t l[];
};

static bignum* bignum_alloc(size_t len) {
  auto res = (bignum*)malloc(sizeof(bignum) + len*sizeof(long));
  res->type = 0;
  res->len = len;
  res->used = 0;
  return res;
}

static bignum* bignum_copy(bignum* a, size_t len) {
  auto res = bignum_alloc(len);
  res->used = a->used;
  memcpy(res->l, a->l, sizeof(uint64_t)*a->used);
  return res;
}

void bignum_set_from_fixnum(bignum*a, uint64_t fix) {
  assert(a->len >= 1);
  a->used = 1;
  a->l[0] = fix;
}

void bignum_print_hex(char* buf, size_t buflen, bignum* a) {
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

bignum* bignum_add_unsigned(bignum* a, bignum* b) {
  // Make a is bigger.
  if (a->used < b->used) {
    bignum* tmp = a;
    a = b;
    b = tmp;
  }
  auto nlen = a->used + 1;
  int carry = 0;
  auto res = bignum_copy(a, nlen);

  // Copy a in to res.
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

void bignum_simplify(bignum* a) {
  while(a->used > 0 && a->l[a->used-1] == 0) {
      a->used--;
  }
  if (a->used == 0) {
    a->used = 1;
  }
}

int bignum_cmp(bignum* a, bignum* b) {
  if (a->used > b->used) {
    return 1;
  } else if (b->used > a->used) {
    return -1;
  } else {
    for(int64_t i = a->used-1; i >=0; i--) {
      if (a->l[i] > b->l[i]) {
	return 1;
      } else if (b->l[i] > a->l[i]) {
	return -1;
      }
    }
  }
  
  return 0;
}

bignum* bignum_sub_unsigned(bignum* a, bignum* b) {
  // a *MUST* be bigger.
  assert(a->used >= b->used);
  assert(bignum_cmp(b, a) != 1);
  auto nlen = a->used;
  int borrow = 0;
  auto res = bignum_copy(a, nlen);

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
  bignum_simplify(res);
  return res;
}

bignum* bignum_mul_unsigned(bignum* a, bignum* b) {
  // Make a smaller.
  if (a->used > b->used) {
    bignum* tmp = a;
    a = b;
    b = tmp;
  }
  assert(a->used <= b->used);

  
  auto nlen = a->used + b->used;
  auto res = bignum_alloc(nlen);
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

  bignum_simplify(res);
  return res;
}

static void bignum_destructive_shift_left_word(bignum* a, uint64_t words) {
  assert(a->len - a->used > words);
  int64_t i;
  for(i = a->used - 1; i >= words; i--) {
    a->l[i] = a->l[i - words];
  }
  a->used += words;
  for(;  i >= 0; i--) {
    a->l[i] = 0;
  }
}

static void bignum_destructive_shift_left(bignum* a, uint64_t bits) {
  auto words = bits / 64;
  if (words) {
    bignum_destructive_shift_left_word(a, words);
    bits -= words * 64;
  }
  assert(a->len > a->used);
  a->used++;
  a->l[a->used-1] = 0;
  if (bits) {
    int i;
    for(i = a->used - 1; i > 0; i--) {
      a->l[i] = (a->l[i] << bits) | (a->l[i-1] >> (64 - bits));
    }
    a->l[0] <<= bits;
  }
  bignum_simplify(a);
}

static void bignum_destructive_shift_right_word(bignum* a, uint64_t words) {
  int64_t i;
  for(i = 0; i < a->used - words; i++) {
    a->l[i]  = a->l[i + words];
  }
  for(; i < a->used; i++) {
    a->l[i] = 0;
  }
  a->used -= words;
}

static void bignum_destructive_shift_right(bignum* a, uint64_t bits) {
  auto words = bits/ 64;
  if (words) {
    bignum_destructive_shift_right_word(a, words);
    bits -= words * 64;
  }
  if (bits) {
    int i;
    for(i = 0; i < a->used-1; i++) {
      a->l[i] = (a->l[i] >> bits) | (a->l[i + 1] << (64 - bits));
    }
    a->l[i] >>= bits;
  }
  bignum_simplify(a);
}

bool bignum_is_zero(bignum* a) {
  return a->used == 1 && a->l[0] == 0;
}

static void bignum_destructive_or(bignum* res, bignum* o) {
  auto v = res->used < o->used ? res->used : o->used;

  for(uint64_t i = 0; i < v; i++) {
    res->l[i] |= o->l[i];
  }
}

bignum* bignum_div(bignum* a, bignum* b) {
  bignum* c = bignum_alloc(a->used + 1);
  bignum_set_from_fixnum(c, 1);
  if(bignum_cmp(a, b) != 1) {
    bignum_set_from_fixnum(c, 0);
    return c;
  }
  assert(!bignum_is_zero(b));

  bignum* denom = bignum_copy(b, a->used + 1);
  bignum* num = bignum_copy(a, a->used + 1);

  while(bignum_cmp(denom, a) != 1) {
    bignum_destructive_shift_left(denom, 1);
    bignum_destructive_shift_left(c, 1);
  }
  bignum* res = bignum_alloc(a->used);
  memset(res->l, 0, sizeof(uint64_t)*a->used);
  res->used = a->used;

  while(!bignum_is_zero(c)) {
    if (bignum_cmp(num, denom) != -1) {
      num = bignum_sub_unsigned(num, denom);
      bignum_destructive_or(res, c);
    }
    bignum_destructive_shift_right(c, 1);
    bignum_destructive_shift_right(denom, 1);
  }

  bignum_simplify(res);
  return res;
}

#include <gmp.h>



int nlz(unsigned x) {
   int n;

   if (x == 0) return(32);
   n = 0;
   if (x <= 0x0000FFFF) {n = n +16; x = x <<16;}
   if (x <= 0x00FFFFFF) {n = n + 8; x = x << 8;}
   if (x <= 0x0FFFFFFF) {n = n + 4; x = x << 4;}
   if (x <= 0x3FFFFFFF) {n = n + 2; x = x << 2;}
   if (x <= 0x7FFFFFFF) {n = n + 1;}
   return n;
}

/* q[0], r[0], u[0], and v[0] contain the LEAST significant words.
(The sequence is in little-endian order).

This is a fairly precise implementation of Knuth's Algorithm D, for a
binary computer with base b = 2**32. The caller supplies:
   1. Space q for the quotient, m - n + 1 words (at least one).
   2. Space r for the remainder (optional), n words.
   3. The dividend u, m words, m >= 1.
   4. The divisor v, n words, n >= 2.
The most significant digit of the divisor, v[n-1], must be nonzero.  The
dividend u may have leading zeros; this just makes the algorithm take
longer and makes the quotient contain more leading zeros.  A value of
NULL may be given for the address of the remainder to signify that the
caller does not want the remainder.
   The program does not alter the input parameters u and v.
   The quotient and remainder returned may have leading zeros.  The
function itself returns a value of 0 for success and 1 for invalid
parameters (e.g., division by 0).
   For now, we must have m >= n.  Knuth's Algorithm D also requires
that the dividend be at least as long as the divisor.  (In his terms,
m >= 0 (unstated).  Therefore m+n >= n.) */

int divmnu(unsigned q[], unsigned r[],
     const unsigned u[], const unsigned v[],
     int m, int n) {

   const unsigned long long b = 4294967296LL; // Number base (2**32).
   unsigned *un, *vn;                         // Normalized form of u, v.
   unsigned long long qhat;                   // Estimated quotient digit.
   unsigned long long rhat;                   // A remainder.
   unsigned long long p;                      // Product of two digits.
   long long t, k;
   int s, i, j;

   if (m < n || n <= 0 || v[n-1] == 0)
      return 1;                         // Return if invalid param.

   if (n == 1) {                        // Take care of
      k = 0;                            // the case of a
      for (j = m - 1; j >= 0; j--) {    // single-digit
         q[j] = (k*b + u[j])/v[0];      // divisor here.
         k = (k*b + u[j]) - q[j]*v[0];
      }
      if (r != NULL) r[0] = k;
      return 0;
   }

   /* Normalize by shifting v left just enough so that its high-order
   bit is on, and shift u left the same amount. We may have to append a
   high-order digit on the dividend; we do that unconditionally. */

   s = nlz(v[n-1]);             // 0 <= s <= 31.
   vn = (unsigned *)alloca(4*n);
   for (i = n - 1; i > 0; i--)
      vn[i] = (v[i] << s) | ((unsigned long long)v[i-1] >> (32-s));
   vn[0] = v[0] << s;

   un = (unsigned *)alloca(4*(m + 1));
   un[m] = (unsigned long long)u[m-1] >> (32-s);
   for (i = m - 1; i > 0; i--)
      un[i] = (u[i] << s) | ((unsigned long long)u[i-1] >> (32-s));
   un[0] = u[0] << s;

   for (j = m - n; j >= 0; j--) {       // Main loop.
      // Compute estimate qhat of q[j].
      qhat = (un[j+n]*b + un[j+n-1])/vn[n-1];
      rhat = (un[j+n]*b + un[j+n-1]) - qhat*vn[n-1];
again:
      if (qhat >= b || qhat*vn[n-2] > b*rhat + un[j+n-2])
      { qhat = qhat - 1;
        rhat = rhat + vn[n-1];
        if (rhat < b) goto again;
      }

      // Multiply and subtract.
      k = 0;
      for (i = 0; i < n; i++) {
         p = qhat*vn[i];
         t = un[i+j] - k - (p & 0xFFFFFFFFLL);
         un[i+j] = t;
         k = (p >> 32) - (t >> 32);
      }
      t = un[j+n] - k;
      un[j+n] = t;

      q[j] = qhat;              // Store quotient digit.
      if (t < 0) {              // If we subtracted too
         q[j] = q[j] - 1;       // much, add back.
         k = 0;
         for (i = 0; i < n; i++) {
            t = (unsigned long long)un[i+j] + vn[i] + k;
            un[i+j] = t;
            k = t >> 32;
         }
         un[j+n] = un[j+n] + k;
      }
   } // End j.
   // If the caller wants the remainder, unnormalize
   // it and pass it back.
   if (r != NULL) {
      for (i = 0; i < n-1; i++)
         r[i] = (un[i] >> s) | ((unsigned long long)un[i+1] << (32-s));
      r[n-1] = un[n-1] >> s;
   }
   return 0;
}

bignum* bignum_div2(bignum* num, bignum* denom) {
  if(bignum_cmp(num, denom) != 1) {
    auto c = bignum_alloc(1);
    bignum_set_from_fixnum(c, 0);
    return c;
  }
  assert(!bignum_is_zero(denom));
  
  auto res = bignum_alloc(num->used);
  res->used = num->used;
  memset(res->l, 0, res->len*sizeof(uint64_t));
  auto denom_used = denom->used*2;
  if (((unsigned*)denom->l)[denom_used-1] == 0) denom_used--;
  auto r = divmnu((unsigned*)res->l, nullptr,
		  (unsigned*)num->l, (unsigned*)denom->l,
		  num->used*2, denom_used);
  assert(r == 0);
  bignum_simplify(res);
  return res;
}

// int main() {
//   uint64_t inputs[512];
//   memset(inputs, 0, sizeof(inputs));

//   size_t sz = fread(inputs, 1, 512 * sizeof(uint64_t), stdin);
//   sz /= sizeof(uint64_t);
  
//   auto a = bignum_alloc(2);
//   auto d = bignum_alloc(1);
//   bignum_set_from_fixnum(a, 2);
//   bignum_set_from_fixnum(d, 1);

//   mpz_t am;
//   mpz_t bm;
//   mpz_t dm;
  
//   mpz_inits(am, bm, dm, nullptr);
//   mpz_set_ui(am, 2);
//   mpz_set_ui(dm, 1);
  
//   for(uint64_t i =0; i < sz; i++) {
//     auto in = inputs[i];
//     if (in < 2) {
//       continue;
//     }
//     auto b = bignum_alloc(1);
    
//     bignum_set_from_fixnum(b, in);
//     mpz_set_ui(bm, in);

//     bignum*res;
//     res = bignum_mul_unsigned(a, b);
//     mpz_mul(am, am, bm);
//     mpz_add(dm, dm, bm);
//     free(a);
//     a = res;

//     res = bignum_add_unsigned(d, b);
//     free(b);
//     free(d);
//     d = res;
//   }
//   {
//     char buf1[1024];
//     bignum_print_hex(buf1, 1024, a);
//     printf("A: %s\n", buf1);
//   }
//   {
//     char buf1[1024];
//     bignum_print_hex(buf1, 1024, d);
//     printf("D: %s\n", buf1);
//   }
//   assert(bignum_cmp(a, d) == 1);
//   auto olda = a;
//   a = bignum_div2(a, d);
//   free(olda);
//   char buf1[1024];
//   bignum_print_hex(buf1, 1024, a);
//   printf("%s\n", buf1);

//   free(d);
//   free(a);

//   char buf2[1024];
//   gmp_printf("A: %Zx\n", am);
//   gmp_printf("D: %Zx\n", dm);
//   mpz_tdiv_q(am, am, dm);
//   gmp_snprintf(buf2, 1024, "%Zx", am);
//   printf("%s\n", buf2);
//   assert(strcmp(buf2, buf1) == 0);

//   mpz_clears(am, bm, dm, nullptr);
//   return 0;
// }

bignum* expt(bignum* num, uint64_t exp) {
  auto res = bignum_copy(num, num->used);
  for(uint64_t i = 0; i < exp - 1; i++) {
    res = bignum_mul_unsigned(res, num);
  }
  return res;
}

bignum* exact_integer_sqrt(bignum * s) {
  auto res = bignum_alloc(1);
  bignum_set_from_fixnum(res, 1);
  if (bignum_cmp(s, res) != 1) {
    return s;
  }
  bignum_set_from_fixnum(res, 2);
  auto x0 = bignum_div2(s, res);
  auto x1 = bignum_div2( bignum_add_unsigned(x0, bignum_div2(s, x0)), res);
  while(bignum_cmp(x1, x0) == -1) {
    x0 = x1;
    x1 = bignum_div2(bignum_add_unsigned(x0, (bignum_div2(s, x0))), res);
  }
  return x0;
}

bignum* square(bignum* a) {
  return bignum_mul_unsigned(a, a);
}

int main(int argc, char* argv[]) {
  int nb_digits = atoi(argv[1]);
  auto one = bignum_alloc(1);
  bignum_set_from_fixnum(one, 10);
  one = expt(one, nb_digits);

  auto two = bignum_alloc(1);
  bignum_set_from_fixnum(two, 2);

  auto four = bignum_alloc(1);
  bignum_set_from_fixnum(four, 4);

  auto oneone = bignum_alloc(1);
  bignum_set_from_fixnum(oneone, 1);

  auto a = one;
  auto b = exact_integer_sqrt(bignum_div2(square(one), two));
  auto t = bignum_div2(one, four);
  auto x = oneone;
  bignum* res;
  while (true) {
  // {
  //   char buf1[1024];
  //   bignum_print_hex(buf1, 1024, a);
  //   printf("A: %s\n", buf1);
  // }
  // {
  //   char buf1[1024];
  //   bignum_print_hex(buf1, 1024, b);
  //   printf("B: %s\n", buf1);
  // }
  // {
  //   char buf1[1024];
  //   bignum_print_hex(buf1, 1024, t);
  //   printf("T: %s\n", buf1);
  // }
  // {
  //   char buf1[1024];
  //   bignum_print_hex(buf1, 1024, x);
  //   printf("X: %s\n", buf1);
  // }
    if (bignum_cmp(a, b) == 0) {
      res = bignum_div2(square(bignum_add_unsigned(a, b)), bignum_mul_unsigned(four, t));
      break;
    }
    auto newa = bignum_div2(bignum_add_unsigned(a, b), two);
    auto diff = bignum_cmp(newa, a) == 1 ? bignum_sub_unsigned(newa, a) : bignum_sub_unsigned(a, newa);
    auto newb = exact_integer_sqrt(bignum_mul_unsigned(a, b));
    auto foo = bignum_mul_unsigned(x, square(diff));
    auto the_div2 = bignum_div2(foo, one);
    auto newt = bignum_sub_unsigned(t, the_div2);
    auto newx = bignum_mul_unsigned(two, x);
    a = newa;
    b = newb;
    t = newt;
    x = newx;
  }
  
  {
    char buf1[10240];
    bignum_print_hex(buf1, 10240, res);
    printf("A: %s\n", buf1);
  }
  return 0;
}

