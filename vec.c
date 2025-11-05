// Copyright 2023 Dave Watson

#include "vec.h"

#include <stdio.h>

vec_header_t *vec_header(void *arr) { return (vec_header_t *)arr - 1; }
void arr_grow(void **arr, size_t elemsize, size_t min_cap) {
  vec_header_t *h = nullptr;
  if (*arr) {
    h = vec_header(*arr);
  }
  size_t new_cap = min_cap;
  if (h && new_cap < h->cap * 2) {
    new_cap = h->cap * 2;
  }
  if (new_cap < 4) {
    new_cap = 4;
  }
  vec_header_t *res = realloc(h, sizeof(vec_header_t) + (elemsize * new_cap));
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
