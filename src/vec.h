// Copyright 2023 Dave Watson

#pragma once

#include <assert.h>
#include <stdlib.h>

#include "defs.h"

typedef struct {
  size_t len;
  size_t cap;
} arr_header_t;

void arr_grow(void **arr, size_t elemsize, size_t min_cap);

arr_header_t *arr_header(void *arr);

// Yet another dynamic vector implementation.
// This one uses real functions, so that it doesn't piss off any linters.
// We assume LTO will inline most of it - and we could add 'static inline'
// if we wanted instead.
//
// The main downside is the need for VEC_TYPE_IMPL/DEF somewhere, and the need
// to append a name for each type, since typeof() runs after the preprocessor.


#define VEC_TYPE_DEF(name, dtype)                                              \
  void arrfree_##name(dtype **arr);                                            \
  size_t arrlen_##name(dtype *arr);                                            \
  void arrsetlen_##name(dtype **arr, size_t len);                              \
  void arrpush_##name(dtype **arr, dtype v);                                   \
  dtype arrpop_##name(dtype *arr);                                             \
  dtype arrlast_##name(dtype *arr);

#define VEC_TYPE_IMPL(name, dtype)                                             \
  void arrfree_##name(dtype **arr) {                                           \
    if (*arr) {                                                                \
      free(arr_header(*arr));                                                  \
      *arr = nullptr;                                                          \
    }                                                                          \
  }                                                                            \
  size_t arrlen_##name(dtype *arr) {                                           \
    if (arr) {                                                                 \
      return arr_header(arr)->len;                                             \
    }                                                                          \
    return 0;                                                                  \
  }                                                                            \
  void arrsetlen_##name(dtype **arr, size_t len) {                             \
    if ((*arr) == nullptr || len > arr_header(*arr)->cap) {                    \
      arr_grow((void **)arr, sizeof(dtype), len);                              \
    }                                                                          \
    arr_header(*arr)->len = len;                                               \
  }                                                                            \
  void arrpush_##name(dtype **arr, dtype v) {                                  \
    if ((*arr) == nullptr ||                                                   \
        arr_header(*arr)->len + 1 > arr_header(*arr)->cap) {                   \
      arr_grow((void **)arr, sizeof(dtype),                                    \
               *arr ? (arr_header(*arr)->len + 1) : 1);                        \
    }                                                                          \
    (*arr)[arr_header(*arr)->len++] = v;                                       \
  }                                                                            \
  dtype arrpop_##name(dtype *arr) {                                            \
    assert(arr);                                                               \
    auto h = arr_header(arr);                                                  \
    return arr[--h->len];                                                      \
  }                                                                            \
  dtype arrlast_##name(dtype *arr) {                                           \
    assert(arr);                                                               \
    auto h = arr_header(arr);                                                  \
    return arr[h->len - 1];                                                    \
  }
