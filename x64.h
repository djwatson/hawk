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
void emit_reg_reg(uint8_t opcode, uint8_t src, uint8_t dst);

enum jcc_cond {
  JA = 0x87,
  JAE = 0x83,
  JB = 0x82,
  JBE = 0x86,
  JC = 0x82,
  JE = 0x84,
  JZ = 0x84,
  JG = 0x8f,
  JGE = 0x8d,
  JL = 0x8c,
  JLE = 0x8e,
  JNA = 0x86,
  JNAE = 0x82,
  JNB = 0x83,
  JBC = 0x83,
  JNC = 0x83,
  JNE = 0x85,
  JNG = 0x8e,
  JNGE = 0x8c,
  JNL = 0x8b,
  JNLE = 0x8f,
  JNO = 0x81,
  JNP = 0x8b,
  JNS = 0x89,
  JNZ = 0x85,
  JO = 0x80,
  JP = 0x8a,
  JPE = 0x8a,
  JPO = 0x8b,
  JS = 0x88,
};
void emit_jcc32(enum jcc_cond cond, int64_t offset);
