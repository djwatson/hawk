#pragma once

#include <stdint.h>

#include <vector>

// clang-format off
enum class ir_ins_op : uint8_t {
  LT,
  GE,
  LE,
  GT,

  CLT,

  EQ,
  NE,
  NOP,
  KFIX,
  KFUNC,
  GGET,
  RET,
  CALL,
  SLOAD,
  ARG,

  ADD,
  SUB,
  MUL,
  DIV,

  LOOP,
  PHI,

  CAR,
  CDR,
    
  ALLOC,
  REF,
  VREF,
  STORE,
  LOAD,

  ABC,
};

extern const char *ir_names[];

#define IR_CONST_BIAS 0x8000

#define IR_INS_TYPE_GUARD 0x80
// clang-format on

struct ir_ins {
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
};

// TODO this probably isn't correct, could smash large pointers.
#define SNAP_FRAME 0x8000000000000000

struct snap_entry_s {
  int16_t slot;
  uint16_t val;
};

struct snap_s {
  uint32_t *pc;
  uint16_t ir;
  uint16_t offset;
  uint8_t exits;
  int link;
  std::vector<snap_entry_s> slots;
  uint64_t patchpoint;
};

enum trace_type_e {
  TRACE_RETURN,
  TRACE_TAILREC,
};

enum reloc_type {
  RELOC_ABS,
  RELOC_SYM_ABS,
};

struct reloc {
  uint64_t offset;
  long obj;
  reloc_type type;
};

typedef long (*Func)(long **, unsigned int **);
typedef struct trace_s {
  std::vector<ir_ins> ops;
  std::vector<long> consts;
  reloc* relocs;
  snap_s* snaps;
  int link;
  unsigned int startpc;
  int num;
  Func fn = nullptr;
} trace_s;

#define UNROLL_LIMIT 1

#define ir_is_const(op) (op&IR_CONST_BIAS)
