// Copyright 2023 Dave Watson

#pragma once

#include <stdint.h>

#include "types.h"

extern const char *ins_names[];
extern gc_obj *const_table;
extern uint64_t const_table_sz;

#define CODE(i, a, b, c) (((c) << 24) | ((b) << 16) | ((a) << 8) | (i))
#define CODE_D(i, a, d) (((d) << 16) | ((a) << 8) | (i))
static inline uint8_t INS_OP(uint32_t i) { return i & 0xff; }
#define INS_A(i) (((i) >> 8) & 0xff)
#define INS_B(i) (((i) >> 16) & 0xff)
#define INS_C(i) (((i) >> 24) & 0xff)
#define INS_D(i) ((i) >> 16)

typedef struct bcfunc {
  char *name;
  uint32_t codelen;
  uint8_t poly_cnt;
  uint32_t code[];
} bcfunc;
