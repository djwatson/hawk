#pragma once

#include <stdint.h>

// clang-format off
typedef enum {
  IR_LT,
  IR_GE,
  IR_LE,
  IR_GT,

  IR_CLT,

  IR_EQ,
  IR_NE,
  IR_NOP,
  IR_KFIX,
  IR_KFUNC,
  IR_GGET,
  IR_GSET,
  IR_RET,
  IR_CALL,
  IR_SLOAD,
  IR_ARG,

  IR_ADD,
  IR_SUB,
  IR_MUL,
  IR_DIV,

  IR_LOOP,
  IR_PHI,

  IR_CAR,
  IR_CDR,
    
  IR_ALLOC,
  IR_REF,
  IR_STRREF,
  IR_VREF,
  IR_STORE,
  IR_STRST,
  IR_LOAD,
  IR_STRLD,

  IR_ABC,

  IR_CALLXS,
  IR_CARG,

  IR_NONE,
} ir_ins_op;

extern const char *ir_names[];

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
  uint8_t exits;
  int link;
  snap_entry_s *slots;
  uint64_t patchpoint;
  uint64_t depth;
} snap_s;

typedef enum {
  TRACE_RETURN,
  TRACE_TAILREC,
} trace_type_e;

typedef enum {
  RELOC_ABS,
  RELOC_SYM_ABS,
} reloc_type;

typedef struct {
  uint64_t offset;
  long obj;
  reloc_type type;
} reloc;

typedef long (*Func)(long **, unsigned int **);
typedef struct {
  ir_ins *ops;
  long *consts;
  reloc *relocs;
  snap_s *snaps;
  int link;
  unsigned int startpc;
  int num;
  Func fn;
} trace_s;

#define UNROLL_LIMIT 1

#define ir_is_const(op) (op & IR_CONST_BIAS)

uint32_t push_ir(trace_s*trace, ir_ins_op op, uint32_t op1, uint32_t op2, uint8_t type);
