#pragma once

#include <stdint.h>
typedef struct symbol symbol;

// clang-format off
typedef enum {
  IR_LT,
  IR_GE,
  IR_LE,
  IR_GT,

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
  IR_REM,
  IR_AND,

  IR_SHR,

  IR_LOOP,
  IR_PHI,

  IR_CAR,
  IR_CDR,
    
  IR_ALLOC,
  IR_GCLOG,
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
  IR_FLUSH,
  IR_CCRES,
  IR_SAVEAP,
  IR_RESAP,

  IR_CHGTYPE,

  IR_NONE,
} ir_ins_op;

typedef enum {
  SLOAD_PARENT = 1 <<0, // Loaded from parent.
  SLOAD_TYPED = 1 << 1, // Already typechecked (at parent).
} ir_sload_tag;

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
  long obj;
  reloc_type type;
} reloc;

typedef long (*Func)(long **, unsigned int **);
typedef struct trace_s_s {
  struct trace_s_s *next;
  ir_ins *ops;
  long *consts;
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

#define UNROLL_LIMIT 2
#define UNROLL_ABORT_LIMIT 5

#define ir_is_const(op) (op & IR_CONST_BIAS)

uint32_t push_ir(trace_s *trace, ir_ins_op op, uint32_t op1, uint32_t op2,
                 uint8_t type);
