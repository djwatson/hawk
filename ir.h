#pragma once


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

  ADD,
  SUB,
  MUL,
  DIV,
};

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
