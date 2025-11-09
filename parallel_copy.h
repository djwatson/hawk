// Copyright 2023 Dave Watson
#pragma once

#include <stdint.h>

typedef struct par_copy {
  uint64_t from;
  uint64_t to;
} par_copy;

par_copy *serialize_parallel_copy(par_copy *moves, uint64_t tmp_reg);
