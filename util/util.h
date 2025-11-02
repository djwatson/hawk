#pragma once

#include <stdint.h>

#define likely(x) __builtin_expect(x, 1)
#define unlikely(x) __builtin_expect(x, 0)
#define NOINLINE __attribute__((noinline))
#define INLINE __attribute__((always_inline))

static inline uintptr_t align(uintptr_t val, uintptr_t alignment) {
  return (val + alignment - 1) & ~(alignment - 1);
}

static inline uint64_t hashmix(uint64_t key) {
  key += (key << 10);
  key ^= (key >> 6);
  return key;
}
