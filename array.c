// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "array.h"
#include "hawk.h"

void *arrgrowf(zone *z, void *a, size_t elemsize, size_t addlen,
               size_t min_cap) {
  size_t new_cap = min_cap + addlen;
  array_header *header = nullptr;
  if (a) {
    header = arr_header(a);

    if (addlen + header->length >= header->capacity) {
      new_cap = header->capacity * 2;
      if (new_cap < min_cap) {
        new_cap = min_cap;
      }
    } else {
      return a;
    }
  }

  array_header *b;
  auto new_size = sizeof(array_header) + (elemsize * new_cap);
  if (z) {
    b = zone_realloc(
        z, header,
        header ? (sizeof(array_header) + (elemsize * header->capacity)) : 0,
        new_size);
  } else {
    b = realloc(header, new_size);
  }
  b->capacity = new_cap;
  if (!header) {
    b->length = 0;
  }

  return (char *)b + sizeof(array_header);
}

array_header *arr_header(void const *t) { return (array_header *)t - 1; }

size_t arrlen(void const *a) {
  if (a) {
    array_header *header = arr_header(a);
    return header->length;
  }
  return 0;
}

void arrlen_set(void const *a, size_t len) {
  if (!a) {
    return;
  }
  array_header *header = arr_header(a);
  assert(len < header->capacity);
  header->length = len;
}

void arr_reverse_elems(void *a, size_t elem_size) {
  if (!a) {
    return;
  }
  size_t len = arrlen(a);
  if (len <= 1) {
    return;
  }
  uint8_t *data = a;
  size_t start = 0;
  size_t end = len - 1;
  while (start < end) {
    for (size_t b = 0; b < elem_size; b++) {
      uint8_t *lhs = data + (start * elem_size) + b;
      uint8_t *rhs = data + (end * elem_size) + b;
      SWAP(uint8_t, *lhs, *rhs);
    }
    start++;
    end--;
  }
}
