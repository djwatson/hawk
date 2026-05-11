// Ftoa
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hawk.h"

#define SCIENTIFIC 10

// Simple shortest-ftoa.
// This will in some cases add a single extra digit, when rounding would provide
// the incorrect result:
//
// Example: 618970019642690137449562112.0
// The shortest roundtrip would end in ...902, not ...9014

// Use of schubfach or zmij or dragonbox would solve this, and be faster.

static uint64_t dbits(double d) {
  uint64_t u;
  memcpy(&u, &d, sizeof u);
  return u;
}

static bool roundtrip_eq(double v, const char *s) {
  char *end = nullptr;
  double parsed = strtod(s, &end);
  if (!end || *end != '\0') {
    return false;
  }
  return dbits(parsed) == dbits(v);
}

static bool append_decimal_if_needed(char *buf, int n, size_t size) {
  if (strpbrk(buf, ".eE")) {
    return true;
  }
  if (n + 2 >= (int)size) {
    return false;
  }
  buf[n] = '.';
  buf[n + 1] = '0';
  buf[n + 2] = '\0';
  return true;
}

static void trim_trailing_zeroes(char *buf) {
  char *dot = strchr(buf, '.');
  if (!dot) {
    return;
  }
  char *end = buf + strlen(buf);
  while (end > dot + 2 && end[-1] == '0') {
    end--;
  }
  *end = '\0';
}

static void trim_scientific_zeroes(char *buf) {
  char *exp = strpbrk(buf, "eE");
  if (!exp) {
    return;
  }

  char *dot = strchr(buf, '.');
  if (!dot || dot > exp) {
    return;
  }

  char *end = exp;
  while (end > dot + 1 && end[-1] == '0') {
    end--;
  }
  if (end == dot + 1) {
    end = dot;
  }
  memmove(end, exp, strlen(exp) + 1);
}

static bool should_use_scientific(double v) {
  double av = fabs(v);
  if (av == 0.0) {
    return false;
  }
  double cutoff = pow(10.0, SCIENTIFIC);
  return av >= cutoff || av < (1.0 / cutoff);
}

static void normalize_exponent(char *buf) {
  char *exp = strpbrk(buf, "eE");
  if (!exp) {
    return;
  }

  char *src = exp + 1;
  char sign = '\0';
  if (*src == '+' || *src == '-') {
    sign = *src;
    src++;
  }
  while (*src == '0' && src[1] != '\0') {
    src++;
  }

  char *dst = exp + 1;
  if (sign == '-') {
    *dst++ = sign;
  }
  memmove(dst, src, strlen(src) + 1);
}

static bool format_regular(double v, char *buf, size_t size) {
  // Try increasing precisions until the string round-trips.
  for (int p = 1; p <= DBL_DECIMAL_DIG; p++) {
    int n = snprintf(buf, size, "%.*f", p, v);
    if (n < 0 || n >= (int)size) {
      continue;
    }
    trim_trailing_zeroes(buf);
    if (roundtrip_eq(v, buf)) {
      return true;
    }
  }
  return false;
}

static bool format_scientific(double v, char *buf, size_t size) {
  // Try increasing precisions until the string round-trips.
  for (int p = 1; p <= DBL_DECIMAL_DIG; p++) {
    int n = snprintf(buf, size, "%.*e", p - 1, v);
    if (n < 0 || n >= (int)size) {
      continue;
    }
    trim_scientific_zeroes(buf);
    normalize_exponent(buf);
    if (roundtrip_eq(v, buf)) {
      return true;
    }
  }
  return false;
}

// Returns malloc'd string; caller frees.
EXPORT char *ftoa_fast(double v) {
  if (isnan(v)) {
    return strdup("+nan.0");
  }
  if (isinf(v)) {
    return strdup(signbit(v) ? "-inf.0" : "+inf.0");
  }

  char buf[131]; // room for optional ".0"
  if (should_use_scientific(v)) {
    if (format_scientific(v, buf, sizeof buf)) {
      return strdup(buf);
    }
  } else if (format_regular(v, buf, sizeof buf)) {
    return strdup(buf);
  }

  // Fallback: maximum safe digits.
  int n = snprintf(buf, sizeof buf, "%.*g", DBL_DECIMAL_DIG, v);
  if (n < 0) {
    return nullptr;
  }
  if (n >= (int)sizeof buf) {
    n = (int)sizeof buf - 1;
  }
  append_decimal_if_needed(buf, n, sizeof buf);
  normalize_exponent(buf);
  return strdup(buf);
}
