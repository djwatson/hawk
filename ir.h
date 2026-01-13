#pragma once

#include "array.h"
#include "stdint.h"
#include "types.h"

typedef struct vm_state vm_state;

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
  uint8_t depth;
  uint8_t exits;
  uint64_t patch_point;
  trace *trace;
} snap;

typedef enum : uint8_t {
  IR_ARG_NONE_NONE,
  IR_ARG_STACK,
  IR_ARG_IR_NONE,
  IR_ARG_IR_IR,
  IR_ARG_REG,
  IR_ARG_OFFSET,
} ir_arg_type;

#define IR_OPS                                                                 \
  X(EQ, ARG_IR_IR)                                                             \
  X(NE, ARG_IR_IR)                                                             \
  X(LT, ARG_IR_IR)                                                             \
  X(GTE, ARG_IR_IR)                                                            \
  X(LTE, ARG_IR_IR)                                                            \
  X(GT, ARG_IR_IR)                                                             \
  X(NOP, ARG_NONE_NONE)                                                        \
  X(ADD, ARG_IR_IR)                                                            \
  X(SUB, ARG_IR_IR)                                                            \
  X(GGET, ARG_IR_NONE)                                                         \
  X(GSET, ARG_IR_IR)                                                           \
  X(RET, ARG_IR_IR)                                                            \
  X(SLOAD, ARG_STACK)                                                          \
  X(TYPECHECK, ARG_IR_NONE)                                                    \
  X(PMOV, ARG_REG)                                                             \
  X(ARG, ARG_REG)                                                              \
  X(GUARD_EQ, ARG_IR_IR)                                                       \
  X(REF, ARG_IR_IR)                                                            \
  X(LOAD, ARG_IR_IR)                                                           \
  X(STORE, ARG_IR_IR)                                                          \
  X(ALLOC, ARG_IR_IR)                                                          \
  X(INEXACT, ARG_IR_NONE)
typedef enum : uint8_t {
#define X(name, type) IR_##name,
  IR_OPS
#undef X
      IR_INS_MAX,
} ir_ins_op;

typedef struct {
  ir_ins_op op;
  uint8_t type : 7;
  uint8_t guard : 1;
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
    // PMOV data
    struct {
      uint8_t prev_reg;
      bool prev_guard;
    };
    uint32_t data;
  };
} ir_ins;

static_assert(sizeof(ir_ins) == 8, "ir_ins instructions must be 8 bytes");

struct trace_result {
  gc_obj *stack;
  snap *snap;
};

typedef struct trace_result (*trace_fn)(vm_state *state, gc_obj *stack);
typedef struct trace {
  uint16_t stackpos;
  ir_ins *ins;
  gc_obj *consts;
  snap *snaps;
  trace_fn fn;
  uint16_t num;
  // TODO can remove parent
  trace *parent;
  snap *parent_snap;
  trace *link;
  uint64_t trace_start;
  bc start_pc;
  trace *next; // Chained polymorphic traces.
} trace;

enum : uint8_t {
  REG_NONE = 0xff,
  SPILL_NONE = 0xff,
};

void print_ir(trace *t);

extern char *ir_names[];
extern ir_arg_type ir_ins_types[];

bool ir_sideeff(ir_ins_op op);
