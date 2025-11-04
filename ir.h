#pragma once

#include "stdint.h"
#include "types.h"
#include "vec.h"

typedef struct {
  bool constant;
  uint16_t loc : 15;
} slot;

#define IR_OPS					\
  X(NOP)					\
  X(LT)					\
  X(ADD)					\
  X(SUB)					\
  X(GGET)					\
  X(GSET)					\
  X(RET)					\
  X(SLOAD)					\
  X(ARG)					\
  X(GUARD_EQ)					\
  X(REF)					\
  X(LOAD)					\
  X(STORE)					
typedef enum : uint8_t {
#define X(name) IR_##name,
  IR_OPS
  #undef X
    IR_INS_MAX,
} ir_ins_op;

typedef struct {
  ir_ins_op op;
  uint8_t type;
  union {
    struct {
      slot op1;
      slot op2;
    };
    uint32_t data;
  };
  union {
    uint16_t prev;
    struct {
      uint8_t reg;
      uint8_t spill; // spill slot.
    };
  };
} ir_ins;

typedef struct {
  uint16_t stackpos;
  ir_ins *ins;
  gc_obj *consts;
} trace;

typedef struct {
  slot regs[257]; // need offset by 1 - to grab -1.
  bool live[257];
  bc* start_ins;
  uint16_t regs_off;
  uint8_t depth;
} trace_state;

enum : uint8_t {
  REG_NONE = 0xff,
  SPILL_NONE = 0xff,
};

void print_ir(trace* t);

VEC_TYPE_DEF(ins, ir_ins);
VEC_TYPE_DEF(consts, gc_obj);
