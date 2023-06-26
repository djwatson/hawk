#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vec {				
  void* data;					
  uint64_t sz;				
  uint64_t mz;				
} vec;					

#define vec_proto(TYPE, TYPEN)				\
  TYPE vec_at_##TYPEN(vec* vec, uint64_t pos);		\
  void vec_push_##TYPEN(vec* vec, TYPE item);           \

#define vec_INIT(var)				\
  vec var = {NULL, 0, 0};			\
void vec_init(vec* vec);                        
void vec_clear(vec* vec);                       

#define vec_gen(TYPE, TYPEN)				\
  TYPE vec_at_##TYPEN(vec* vec, uint64_t pos) {	\
  assert(pos < vec->sz);                       \
  TYPE* ptr = (TYPE*)vec->data;                 \
  return ptr[pos];                             \
}                                               \
                                                \
void vec_push_##TYPEN(vec* vec, TYPE item) {	\
 if (vec->sz == vec->mz) {                      \
   if (vec->mz == 0) {                          \
     vec->mz = 4;                               \
   } else {                                     \
     vec->mz *= 2;                              \
   }                                            \
   vec->data = realloc(vec->data, vec->mz * sizeof(TYPE)); \
 }                                                             \
                                                               \
                                                               \
 TYPE* ptr = (TYPE*)vec->data;                                 \
 ptr[vec->sz++] = item;                                        \
}

#ifdef __cplusplus
}
#endif
