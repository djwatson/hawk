// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
  size_t length;
  size_t capacity;
  uint32_t *table;
  size_t tmp;
} hash_header;
#define ADDROF(type, val) ((typeof(type)[1]){val})

hash_header *hm_header(void const *t);
ptrdiff_t hm_geti_internal(void const *t, size_t elemsize, void *key,
                           size_t keysize, bool string);
bool hm_del_internal(void const *t, size_t elemsize, void *key, size_t keysize,
                     bool string);
void *hm_put_internal(void *t, size_t elemsize, void *key, size_t keysize,
                      bool string);
void hm_free_internal(void *t);

size_t hm_len(void const *t);
// ptrdiff_t hm_geti(T const *t, TK key);
#define hm_geti(t, k)                                                          \
  hm_geti_internal((t), sizeof *(t), ADDROF((t)->key, k), sizeof((t)->key),    \
                   false)
// bool hm_contains(T const*t, TK key);
#define hm_contains(t, k)                                                      \
  (hm_geti_internal(t, sizeof *(t), ADDROF((t)->key, k), sizeof((t)->key),     \
                    false) >= 0)

// TV hm_getv(T const *t, TK key);
#define hm_getv(t, k)                                                          \
  t[hm_geti_internal(t, sizeof *(t), ADDROF((t)->key, k), sizeof((t)->key),    \
                     false)]                                                   \
      .value

// T hm_gets(T const *t, TK key);
#define hm_gets(t, k)                                                          \
  t[hm_geti_internal(t, sizeof *(t), ADDROF((t)->key, k), sizeof((t)->key),    \
                     false)]

// T* hm_get_or_insert(T const *t, TK key);
// #define hm_get_or_insert(t, key) t[hm_geti_internal(t, sizeof *(t), key,
// sizeof(key))] T* hm_getp_null(T const *t, TK key);
#define hm_getp_null(t, k)                                                     \
  (hm_geti_internal(t, sizeof *(t), ADDROF((t)->key, k), sizeof((t)->key),     \
                    false) == -1                                               \
       ? nullptr                                                               \
       : &(t)[hm_header(t)->tmp])

// void hm_put(T* t, TK key, TV value);
#define hm_put(t, k, val)                                                      \
  ((t) = hm_put_internal(t, sizeof *(t), ADDROF((t)->key, k),                  \
                         sizeof((t)->key), false),                             \
   (t)[hm_header(t)->tmp].value = (val))
// void hm_insert(T* t, TK key);
#define hm_insert(t, k)                                                        \
  ((t) = hm_put_internal(t, sizeof *(t), ADDROF((t)->key, k),                  \
                         sizeof((t)->key), false))
// bool hm_del(T* t, TK key);
#define hm_del(t, k)                                                           \
  hm_del_internal(t, sizeof *(t), ADDROF((t)->key, k), sizeof((t)->key), false)

/// String-keyed hash tables.  Does *not* manage key memory.
#define hm_free(a) ((void)hm_free_internal((void *)(a)), (a) = NULL)
#define sh_free(a) hm_free(a)
// ptrdiff_t hm_geti(T const *t, TK key);
#define sh_geti(t, k)                                                          \
  hm_geti_internal((t), sizeof *(t), ADDROF((t)->key, k), sizeof((t)->key),    \
                   true)
// bool sh_contains(T const*t, TK key);
#define sh_contains(t, k)                                                      \
  (hm_geti_internal(t, sizeof *(t), ADDROF((t)->key, k), sizeof((t)->key),     \
                    true) >= 0)

// T sh_getv(T const *t, TK key);
#define sh_getv(t, k)                                                          \
  t[hm_geti_internal(t, sizeof *(t), ADDROF((t)->key, k), sizeof((t)->key),    \
                     true)]                                                    \
      .value

// TV sh_gets(T const *t, TK key);
#define sh_gets(t, k)                                                          \
  t[hm_geti_internal(t, sizeof *(t), ADDROF((t)->key, k), sizeof((t)->key),    \
                     true)]

// sizeof(key))] T* sh_getp_null(T const *t, TK key);
#define sh_getp_null(t, k)                                                     \
  (hm_geti_internal(t, sizeof *(t), ADDROF((t)->key, k), sizeof((t)->key),     \
                    true) == -1                                                \
       ? nullptr                                                               \
       : &(t)[hm_header(t)->tmp])

// void sh_put(T* t, TK key, TV value);
#define sh_put(t, k, val)                                                      \
  ((t) = hm_put_internal(t, sizeof *(t), ADDROF((t)->key, k),                  \
                         sizeof((t)->key), true),                              \
   (t)[hm_header(t)->tmp].value = (val))
// void sh_insert(T* t, TK key);
#define sh_insert(t, k)                                                        \
  ((t) = hm_put_internal(t, sizeof *(t), ADDROF((t)->key, k),                  \
                         sizeof((t)->key), true))
// bool sh_del(T* t, TK key);
#define sh_del(t, k)                                                           \
  hm_del_internal(t, sizeof *(t), ADDROF((t)->key, k), sizeof((t)->key), true)
