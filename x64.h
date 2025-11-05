#pragma once

#include <stdint.h>

enum registers : uint8_t {
  RAX = 0,
  RCX = 1,
  RDX = 2,
  RBX = 3,
  RSP = 4,
  RBP = 5,
  RSI = 6,
  RDI = 7,
  R8 = 8,
  R9 = 9,
  R10 = 10,
  R11 = 11,
  R12 = 12,
  R13 = 13,
  R14 = 14,
  R15 = 15,
  MAX_REG = 16,

    RET_REG = RAX,
};


void restore_callee_regs();
void save_callee_regs();

//
void emit_ret();
void emit_jmp32(int32_t offset);
void emit_mov64(uint8_t r, int64_t imm);
void emit_init();
void emit_cleanup();
int64_t emit_offset();
void emit_advance(int64_t offset);
void emit_bind(uint64_t label, uint64_t jmp);
void emit_check();
