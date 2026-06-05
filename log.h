#pragma once

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define HLOG_CATS(X)                                                           \
  X(gc, 0)                                                                     \
  X(trace, 1)                                                                  \
  X(record, 2)                                                                 \
  X(jit, 3)                                                                    \
  X(regalloc, 4)                                                               \
  X(asm, 5)                                                                    \
  X(ir, 6)

typedef enum {
  HLOG_NONE = 0,
#define X(n, i) HLOG_##n = 1u << (i),
  HLOG_CATS(X)
#undef X
      HLOG_ALL = UINT32_MAX,
} hlog_cat_t;

extern uint32_t hlog_mask;

#define LOG(n, fmt, ...)                                                       \
  do {                                                                         \
    if (hlog_mask & HLOG_##n) {                                                \
      fprintf(stderr, "[" #n "] " fmt "\n" __VA_OPT__(, ) __VA_ARGS__);        \
    }                                                                          \
  } while (0)

static inline bool hlog_one(const char *s, uint32_t *m) {
#define X(n, i)                                                                \
  if (!strcmp(s, #n)) {                                                        \
    return *m |= HLOG_##n, true;                                               \
  }
  HLOG_CATS(X)
#undef X
  return false;
}

static inline bool hlog_parse(const char *s) {
  uint32_t m = {};
  char buf[256];
  snprintf(buf, sizeof buf, "%s", s);

  for (char *p = strtok(buf, ","); p; p = strtok(nullptr, ",")) {
    if (!hlog_one(p, &m)) {
      return false;
    }
  }

  return hlog_mask = m, true;
}
