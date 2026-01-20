// Ftoa
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

// Returns malloc'd string; caller frees.
char *ftoa_fast(double v) {
  if (isnan(v)) {
    return strdup("nan");
  }
  if (isinf(v)) {
    return strdup(signbit(v) ? "-inf" : "+inf");
  }

  // Try increasing precisions until the string round-trips.
  char buf[131]; // room for optional ".0"
  for (int p = 1; p <= DBL_DECIMAL_DIG; p++) {
    int n = snprintf(buf, sizeof buf, "%.*g", p, v);
    if (n < 0 || n >= (int)sizeof buf) {
      continue;
    }
    if (roundtrip_eq(v, buf)) {
      if (!append_decimal_if_needed(buf, n, sizeof buf)) {
        continue;
      }
      return strdup(buf);
    }
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
  return strdup(buf);
}
