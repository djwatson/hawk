#pragma once

#include "stdint.h"
#include "types.h"
#include "vec.h"

typedef struct {
  bool constant : 1;
  uint16_t loc : 15;
} slot;

typedef struct snap_entry {
  uint16_t slot;
  slot val;
} snap_entry;

typedef struct trace trace;
typedef struct {
  bc *pc;
  uint16_t ir;
  uint16_t offset;
  snap_entry *slots;

  // Side trace info
  uint8_t exits;
  trace* trace;
} snap;

#define IR_OPS                                                                 \
  X(NOP)                                                                       \
  X(LT)                                                                        \
  X(ADD)                                                                       \
  X(SUB)                                                                       \
  X(GGET)                                                                      \
  X(GSET)                                                                      \
  X(RET)                                                                       \
  X(SLOAD)                                                                     \
  X(ARG)                                                                       \
  X(GUARD_EQ)                                                                  \
  X(REF)                                                                       \
  X(LOAD)                                                                      \
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
    uint16_t prev;
    struct {
      uint8_t reg;
      uint8_t spill; // spill slot.
    };
  };
  union {
    struct {
      slot op1;
      slot op2;
    };
    uint32_t data;
  };
} ir_ins;

static_assert(sizeof(ir_ins) == 8, "ir_ins instructions must be 8 bytes");

typedef struct trace {
  uint16_t stackpos;
  ir_ins *ins;
  gc_obj *consts;
  snap *snaps;
} trace;

enum : uint8_t {
  REG_NONE = 0xff,
  SPILL_NONE = 0xff,
};

void print_ir(trace *t);

VEC_TYPE_DEF(ins, ir_ins);
VEC_TYPE_DEF(consts, gc_obj);
VEC_TYPE_DEF(snap, snap);
VEC_TYPE_DEF(snap_entry, snap_entry);

extern char *ir_names[];
