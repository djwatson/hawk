// Copyright 2023 Dave Watson

#include "vec.h"

#include <stdio.h>

arr_header_t *arr_header(void *arr) { return (arr_header_t *)arr - 1; }
void arr_grow(void **arr, size_t elemsize, size_t min_cap) {
  arr_header_t *h = NULL;
  if (*arr) {
    h = arr_header(*arr);
  }
  size_t new_cap = min_cap;
  if (h && new_cap < h->cap * 2) {
    new_cap = h->cap * 2;
  }
  if (new_cap < 4) {
    new_cap = 4;
  }
  arr_header_t *res = realloc(h, sizeof(arr_header_t) + elemsize * new_cap);
  if (!res) {
    printf("Can't realloc arr_grow\n");
    abort();
  }
  if (!h) {
    res->len = 0;
  }
  res->cap = new_cap;
  *arr = res + 1;
}
