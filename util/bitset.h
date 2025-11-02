#pragma once

#include <stdint.h>

static inline void bts(uint64_t *bits, uint64_t bit) {
  auto word = bit / 64;
  auto b = bit % 64;
  bits[word] |= 1UL << b;
}
static inline void btr(uint64_t *bits, uint64_t bit) {
  auto word = bit / 64;
  auto b = bit % 64;
  bits[word] &= ~(1UL << b);
}
static inline bool bt(uint64_t const *bits, uint64_t bit) {
  auto word = bit / 64;
  auto b = bit % 64;
  return bits[word] & (1UL << b);
}

bool find_next_bit(uint64_t const *bits, uint64_t maxbit, uint64_t bit,
                   bool invert, uint64_t *result);
