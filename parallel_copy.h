// Copyright 2023 Dave Watson
#pragma once

#include <stdint.h>

#define MAX_MAP_SIZE 32

#ifdef __cplusplus
extern "C" {
#endif
typedef struct par_copy {
  uint64_t from;
  uint64_t to;
} par_copy;

typedef struct map {
  par_copy mp[MAX_MAP_SIZE];
  uint64_t mp_sz;
} map;

void map_insert(map* m, uint64_t key, uint64_t value);
void serialize_parallel_copy(map* moves, map* moves_out, uint64_t tmp_reg);
#ifdef __cplusplus
}
#endif
