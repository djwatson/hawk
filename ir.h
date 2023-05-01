#pragma once


// clang-format off
enum class ir_ins_op : uint8_t {
  LT,
  GE,
  LE,
  GT,

  EQ,
  NE,
  NOP,
  KFIX,
  KFUNC,
  GGET,
  RET,
  CALL,
  SLOAD,

  ADD,
  SUB,
  MUL,
  DIV,
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
