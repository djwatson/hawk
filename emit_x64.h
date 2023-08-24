#pragma once

#include <stdint.h>

enum registers {
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
};

enum ARITH_CODES {
  OP_ARITH_ADD = 0,
  OP_ARITH_SUB = 5,
  OP_ARITH_CMP = 7,
};

enum OPCODES {
  OP_ADD = 0x01,
  OP_SUB = 0x29,
  OP_XCHG = 0x87,
  OP_MOV = 0x89,
  OP_MOV_MR = 0x8b,
  OP_MOV_RM = 0x89,
  OP_MOV8 = 0x88,
  OP_MOV8_MR = 0x8a,
  OP_MOVZX8 = /* 0x0f */ 0xB6,
  OP_NOP = 0x90,
  OP_XOR = 0x90,
  OP_TEST = 0x85,
  OP_TEST_IMM = 0xf7,
  OP_AND_IMM = 0x81,
  OP_CMP_IMM = 0x81,
  OP_CMP = 0x39,
  OP_LEA = 0x8d,
  OP_SAR_CONST = 0xC1,
  OP_SHL_CONST = 0xC1,
  OP_CQO = 0x99,
  OP_IDIV = 0xF7,
};

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

void emit_init();
void emit_cleanup();
uint64_t emit_offset();
void emit_advance(int64_t offset);
void emit_bind(uint64_t label, uint64_t jmp);
void emit_check();

void emit_ret();
void emit_jmp32(int32_t offset);
void emit_jmp_abs(enum registers r);
void emit_jmp_indirect(int32_t offset);
void emit_call_indirect(uint8_t r);
void emit_mov64(uint8_t r, int64_t imm);
void emit_pop(uint8_t r);
void emit_push(uint8_t r);
void emit_mem_reg(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2);
void emit_mem_reg2(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2);
void emit_mem_reg_sib(uint8_t opcode, int32_t offset, uint8_t scale,
                      uint8_t index, uint8_t base, uint8_t reg);
void emit_rex(uint8_t w, uint8_t r, uint8_t x, uint8_t b);
void emit_imm8(uint8_t imm);
void emit_reg_reg(uint8_t opcode, uint8_t src, uint8_t dst);
void emit_jcc32(enum jcc_cond cond, uint64_t offset);
void emit_op_imm32(uint8_t opcode, uint8_t r1, uint8_t r2, int32_t imm);
void emit_cmp_reg_imm32(uint8_t r, int32_t imm);
void emit_arith_imm(enum ARITH_CODES op, uint8_t src, int32_t imm);
