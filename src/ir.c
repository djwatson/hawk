#include "ir.h"
#include "asm_x64.h"
#include "third-party/stb_ds.h"
#include <stdint.h>

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
  "KFUNC ",
  "GGET  ",
  "GSET  ",
  "RET   ",
  "CALL  ",
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

  "CAR   ",
  "CDR   ",
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
