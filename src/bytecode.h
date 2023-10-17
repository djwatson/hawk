// Copyright 2023 Dave Watson

#pragma once

#include <stdint.h>

#include "types.h"

extern const char *ins_names[];
extern gc_obj *const_table;
extern uint64_t const_table_sz;

static inline uint32_t CODE(uint8_t i, uint8_t a, uint8_t b, uint8_t c) {
  return (((c) << 24) | ((b) << 16) | ((a) << 8) | (i));
}
static inline uint32_t CODE_D(uint8_t i, uint8_t a, uint16_t d) {
  return (((d) << 16) | ((a) << 8) | (i));
}
static inline uint8_t INS_OP(uint32_t i) { return i & 0xff; }
static inline uint8_t INS_A(uint32_t i) { return (i >> 8) & 0xff; }
static inline uint8_t INS_B(uint32_t i) { return (i >> 16) & 0xff; }
static inline uint8_t INS_C(uint32_t i) { return (i >> 24) & 0xff; }
static inline uint16_t INS_D(uint32_t i) { return (i >> 16); }

struct tv {
  uint16_t key;
};
typedef struct bcfunc {
  char *name;
  uint32_t codelen;
  uint8_t poly_cnt;
  struct tv *lst;
  uint32_t code[];
} bcfunc;
