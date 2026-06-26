#pragma once

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "hawk.h"

static NOINLINE void *stack_grow(void *data, size_t elem_size, size_t *cap) {
  size_t new_cap = *cap ? *cap * 2 : 256;
  void *new_data = realloc(data, elem_size * new_cap);
  if (!new_data) {
    fprintf(stderr, "stack_grow: out of memory\n");
    abort();
  }
  *cap = new_cap;
  return new_data;
}

#define STACK(name, type)                                                      \
  typedef struct {                                                             \
    type *data;                                                                \
    size_t len;                                                                \
    size_t cap;                                                                \
  } name;                                                                      \
                                                                               \
  INLINE inline static void name##_push(name *s, type v) {                     \
    if (unlikely(s->len == s->cap)) {                                          \
      s->data = stack_grow(s->data, sizeof(*s->data), &s->cap);                \
    }                                                                          \
    s->data[s->len++] = v;                                                     \
  }                                                                            \
                                                                               \
  INLINE inline static type name##_pop(name *s) { return s->data[--s->len]; }
