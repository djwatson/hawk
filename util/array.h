// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#pragma once

#include <stddef.h>
#include <stdlib.h>

typedef struct {
  size_t length;
  size_t capacity;
} array_header;

static inline array_header *arr_header(void const *t) {
  return (array_header *)t - 1;
}

void *arrgrowf(void *a, size_t elemsize, size_t addlen, size_t min_cap);

#define arrfree(a) ((void)((a) ? free(arr_header(a)) : (void)0), (a) = NULL)

// NOLINTBEGIN(clang-analyzer-core.NullDereference)
static inline size_t arrlen(void const *a) {
  if (a) {
    array_header *header = arr_header(a);
    return header->length;
  }
  return 0;
}
#define arrlast(a) (&(a)[arrlen(a) - 1])

#define arr_arrgrow(a, b, c) ((a) = arrgrowf((a), sizeof *(a), (b), (c)))

#define arrmaybegrow(a, n)                                                     \
  ((!(a) || arr_header(a)->length + (n) >= arr_header(a)->capacity)            \
       ? (arr_arrgrow(a, n, n), 0)                                             \
       : 0)

#define arrput(a, v) (arrmaybegrow(a, 1), (a)[arr_header(a)->length++] = (v))

#define arrpop(a) (--arr_header(a)->length)
#define arrpop_last(a) ((a)[--arr_header(a)->length])

void arrlen_set(void const *arr, size_t len);

#define arr_for_each_idx(arr, idx)                                             \
  for (size_t idx = 0; (idx) < arrlen(arr); (idx)++)
#define arr_for_eachp(arr, p)                                                  \
  for (auto(p) = &(arr)[0]; (p) < (arr) + arrlen(arr); (p)++)
// Note: Copies value.
#define arr_for_each(arr, value)                                               \
  for (typeof((arr)[0])(value), *value##_p = &(arr)[0];                        \
       value##_p < (arr) + arrlen(arr) && ((value) = *value##_p, 1);           \
       value##_p++)
// NOLINTEND(clang-analyzer-core.NullDereference)
void arr_reverse_elems(void *arr, size_t elem_size);
#define arr_reverse(arr) arr_reverse_elems((arr), sizeof((arr)[0]))
