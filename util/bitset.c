#include <assert.h>

#include "bitset.h"

bool find_next_bit(uint64_t const *bits, uint64_t maxbit, uint64_t bit,
                   bool invert, uint64_t *result) {
  auto word = bit / 64;
  int64_t b = (int64_t)bit % 64;
  /* printf("find_next_bit word %li b %li\n", word, b); */

  if (bit >= maxbit) {
    return false;
  }

  uint64_t search = bits[word] >> b;
  if (invert) {
    search = ~search;
  }

  auto res = __builtin_ffsll((int64_t)search);
  if (res && res <= (64 - b)) {
    bit += res - 1;
    if (invert) {
      assert(!bt(bits, bit));
    } else {
      assert(bt(bits, bit));
    }
    if (bit >= maxbit) {
      return false;
    }
    *result = bit;
    return true;
  }
  bit += 64 - b;
  assert((bit % 64) == 0);
  [[clang::musttail]] return find_next_bit(bits, maxbit, bit, invert, result);
}
