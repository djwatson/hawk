#include "vector.h"

void vec_init(vec* vec) {
  vec->sz = 0;
  vec->mz = 0;
  vec->data = NULL;
}

void vec_clear(vec* vec) {
  free(vec->data);
  vec->data = NULL;
}

