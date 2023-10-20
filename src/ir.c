// Copyright 2023 Dave Watson

#include "ir.h"

#include <stdint.h>

#include "asm_x64.h"
#include "third-party/stb_ds.h"

ir_arg_type ir_ins_arg_type[] = {
#define X(name, arg) arg,
    IR_INSTRUCTIONS
#undef X
};

// TODO(djwatson) gen from x macro
// clang-format off
const char* ir_names[] = {
  "LT    ",
  "GE    ",
  "LE    ",
  "GT    ",

  "EQ    ",
  "NE    ",
  "NOP   ",
  "KFIX  ",
  "GGET  ",
  "GSET  ",
  "RET   ",
  "SLOAD ",
  "ARG   ",

  "ADD   ",
  "SUB   ",
  "MUL   ",
  "DIV   ",
  "REM   ",
  "AND   ",

  "SHR   ",

  "LOOP  ",
  "PHI   ",

  "ALLOC ",
  "GCLOG ",
  "REF   ",
  "STRREF",
  "VREF  ",
  "STORE ",
  "STRST ",
  "LOAD  ",
  "STRLD ",

  "ABC   ",
  "CALLXS",
  "CARG  ",
  "FLUSH ",
  "CCRES ",
  "SAVEAP",
  "RESAP ",

  "READCH",
  "PEEKCH",
  "CHGTYP",

  "NONE  ",
};
// clang-format on

uint32_t push_ir(trace_s *trace, ir_ins_op op, uint32_t op1, uint32_t op2,
                 uint8_t type) {
  ir_ins ir = {.op1 = op1,
               .op2 = op2,
               .type = type,
               .op = op,
               .reg = REG_NONE,
               .slot = SLOT_NONE};
  uint32_t res = arrlen(trace->ops);
  arrput(trace->ops, ir);

  return res;
}
