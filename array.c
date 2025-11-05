// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>

#include "array.h"

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

void arr_reverse(void **arr) {
  if (!arr || arrlen(arr) == 0) {
    return;
  }
  uint64_t start = 0;
  uint64_t end = arrlen(arr) - 1;
  while (start < end) {
    auto temp = arr[start];
    arr[start] = arr[end];
    arr[end] = temp;

    start++;
    end--;
  }
}
