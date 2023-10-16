// Copyright 2023 Dave Watson
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "types.h"

typedef struct symbol symbol;

typedef enum {
  IR_ARG_NONE_NONE,
  IR_ARG_IR_NONE,
  IR_ARG_SYM_NONE,
  IR_ARG_SYM_IR,
  IR_ARG_IR_TYPE,
  IR_ARG_IR_IR,
  IR_ARG_IR_OFFSET,
} ir_arg_type;

#define IR_INSTRUCTIONS                                                        \
  X(IR_LT, IR_ARG_IR_IR)                                                       \
  X(IR_GE, IR_ARG_IR_IR)                                                       \
  X(IR_LE, IR_ARG_IR_IR)                                                       \
  X(IR_GT, IR_ARG_IR_IR)                                                       \
                                                                               \
  X(IR_EQ, IR_ARG_IR_IR)                                                       \
  X(IR_NE, IR_ARG_IR_IR)                                                       \
  X(IR_NOP, IR_ARG_NONE_NONE)                                                  \
  X(IR_KFIX, IR_ARG_IR_NONE)                                                   \
  X(IR_GGET, IR_ARG_SYM_NONE)                                                  \
  X(IR_GSET, IR_ARG_SYM_IR)                                                    \
  X(IR_RET, IR_ARG_IR_IR)                                                      \
  X(IR_SLOAD, IR_ARG_IR_NONE)                                                  \
  X(IR_ARG, IR_ARG_IR_NONE)                                                    \
                                                                               \
  X(IR_ADD, IR_ARG_IR_IR)                                                      \
  X(IR_SUB, IR_ARG_IR_IR)                                                      \
  X(IR_MUL, IR_ARG_IR_IR)                                                      \
  X(IR_DIV, IR_ARG_IR_IR)                                                      \
  X(IR_REM, IR_ARG_IR_IR)                                                      \
  X(IR_AND, IR_ARG_IR_IR)                                                      \
                                                                               \
  X(IR_SHR, IR_ARG_IR_OFFSET)                                                  \
                                                                               \
  X(IR_LOOP, IR_ARG_NONE_NONE)                                                 \
  X(IR_PHI, IR_ARG_IR_IR)                                                      \
  X(IR_ALLOC, IR_ARG_IR_TYPE)                                                  \
  X(IR_GCLOG, IR_ARG_IR_NONE)                                                  \
  X(IR_REF, IR_ARG_IR_OFFSET)                                                  \
  X(IR_STRREF, IR_ARG_IR_IR)                                                   \
  X(IR_VREF, IR_ARG_IR_IR)                                                     \
  X(IR_STORE, IR_ARG_IR_IR)                                                    \
  X(IR_STRST, IR_ARG_IR_IR)                                                    \
  X(IR_LOAD, IR_ARG_IR_NONE)                                                   \
  X(IR_STRLD, IR_ARG_IR_IR)                                                    \
                                                                               \
  X(IR_ABC, IR_ARG_IR_IR)                                                      \
                                                                               \
  X(IR_CALLXS, IR_ARG_IR_IR)                                                   \
  X(IR_CARG, IR_ARG_IR_IR)                                                     \
  X(IR_FLUSH, IR_ARG_NONE_NONE)                                                \
  X(IR_CCRES, IR_ARG_IR_IR)                                                    \
  X(IR_SAVEAP, IR_ARG_NONE_NONE)                                               \
  X(IR_RESAP, IR_ARG_NONE_NONE)                                                \
                                                                               \
  X(IR_CHGTYPE, IR_ARG_IR_NONE)                                                \
                                                                               \
  X(IR_NONE, IR_ARG_NONE_NONE)

typedef enum {
#define X(name, arg) name,
  IR_INSTRUCTIONS
#undef X
} ir_ins_op;

typedef enum {
  SLOAD_PARENT = 1 << 0, // Loaded from parent.
  SLOAD_TYPED = 1 << 1,  // Already typechecked (at parent).
} ir_sload_tag;

extern const char *ir_names[];

#define REGS_NONE 0xffff
#define IR_CONST_BIAS 0x8000

#define IR_INS_TYPE_GUARD 0x80
// clang-format on

typedef struct {
  uint16_t op1;
  uint16_t op2;
  uint8_t type;
  ir_ins_op op;
  union {
    uint16_t prev;
    struct {
      uint8_t reg;
      uint8_t slot;
    };
  };
} ir_ins;

typedef struct snap_entry {
  int16_t slot;
  uint16_t val;
} snap_entry_s;

typedef struct {
  uint32_t *pc;
  uint16_t ir;
  uint16_t offset;
  snap_entry_s *slots;
  uint64_t patchpoint;
  uint8_t depth;
  uint8_t exits;
  uint8_t argcnt;
} snap_s;

typedef enum {
  TRACE_RETURN,
  TRACE_TAILREC,
} trace_type_e;

typedef enum {
  RELOC_ABS,
  RELOC_ABS_NO_TAG,
  RELOC_SYM_ABS,
} reloc_type;

typedef struct {
  uint64_t offset;
  gc_obj obj;
  reloc_type type;
} reloc;

typedef gc_obj (*Func)(gc_obj **, unsigned int **);
typedef struct trace_s_s {
  struct trace_s_s *next;
  ir_ins *ops;
  gc_obj *consts;
  reloc *relocs;
  snap_s *snaps;
  int link;
  unsigned int startpc;
  int num;
  Func fn;
  // For flushing
  uint32_t *start;
  struct trace_s_s *parent;
  // For opt
  uint16_t *syms;
} trace_s;

#define UNROLL_LIMIT 1
#define UNROLL_ABORT_LIMIT 5

static inline bool ir_is_const(const uint16_t op) { return op & IR_CONST_BIAS; }
static inline bool is_type_guard(const uint8_t type) {
  return type & IR_INS_TYPE_GUARD;
}
static inline uint8_t get_type(const uint8_t type) {
  return type & ~IR_INS_TYPE_GUARD;
}

uint32_t push_ir(trace_s *trace, ir_ins_op op, uint32_t op1, uint32_t op2,
                 uint8_t type);
extern ir_arg_type ir_ins_arg_type[];
