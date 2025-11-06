// Copyright 2024 Dave Watson

#pragma once

#include <stdint.h>

#define ASM_AARCH64_REGISTER_LIST(X)                                           \
  X(X0)                                                                        \
  X(X1)                                                                        \
  X(X2)                                                                        \
  X(X3)                                                                        \
  X(X4)                                                                        \
  X(X5)                                                                        \
  X(X6)                                                                        \
  X(X7)                                                                        \
  X(X8)                                                                        \
  X(X9)                                                                        \
  X(X10)                                                                       \
  X(X11)                                                                       \
  X(X12)                                                                       \
  X(X13)                                                                       \
  X(X14)                                                                       \
  X(X15)                                                                       \
  X(X16)                                                                       \
  X(X17)                                                                       \
  X(X18)                                                                       \
  X(X19)                                                                       \
  X(X20)                                                                       \
  X(X21)                                                                       \
  X(X22)                                                                       \
  X(X23)                                                                       \
  X(X24)                                                                       \
  X(X25)                                                                       \
  X(X26)                                                                       \
  X(X27)                                                                       \
  X(X28)                                                                       \
  X(X29)                                                                       \
  X(X30)                                                                       \
  X(XZR)

enum registers : uint8_t {
#define X(name) name,
  ASM_AARCH64_REGISTER_LIST(X)
#undef X
      MAX_REG,

  RET_REG = X0,
  RET_REG2 = X1,
  RSTACK = X6,
  RTMP = X7,
  FP = X29,
  LR = X30,
  SP = XZR,
};

void asm_mark_unallocatable(bool used[MAX_REG]);

enum ARITH_CODES {
  ASM_ARITH_ADD = 0,
  ASM_ARITH_SUB = 5,
  ASM_ARITH_CMP = 7,
  ASM_ARITH_NONE = 255,
};

enum OPCODES {
  ASM_ADD = 0x01,
  ASM_SUB = 0x29,
  ASM_XCHG = 0x87,
  ASM_MOV = 0x89,
  ASM_MOV_MR = 0x8b,
  ASM_MOV_RM = 0x89,
  ASM_MOV8 = 0x88,
  ASM_MOV8_MR = 0x8a,
  ASM_MOVZX8 = /* 0x0f */ 0xB6,
  ASM_NOP = 0x90,
  ASM_XOR = 0x31,
  ASM_TEST = 0x85,
  ASM_TEST_IMM = 0xf7,
  ASM_AND_IMM = 0x81,
  ASM_CMP_IMM = 0x81,
  ASM_CMP = 0x39,
  ASM_LEA = 0x8d,
  ASM_AND = 0x83,
  ASM_SAR_CONST = 0xC1,
  ASM_SHL_CONST = 0xC1,
  ASM_CQO = 0x99,
  ASM_IDIV = 0xF7,
  ASM_IMUL = 0xAF,
};

enum jcc_cond {
  JA = 0x87,
  JAE = 0x83,
  JB = 0x82,
  JBE = 0x86,
  JE = 0x84,
  JG = 0x8f,
  JGE = 0x8d,
  JL = 0x8c,
  JLE = 0x8e,
  JNE = 0x85,
  JNO = 0x81,
  JNS = 0x89,
  JO = 0x80,
  JP = 0x8a,
  JS = 0x88,
  // JC = 0x82,
  // JZ = 0x84,
  // JNA = 0x86,
  // JNAE = 0x82,
  // JNB = 0x83,
  // JBC = 0x83,
  // JNC = 0x83,
  // JNG = 0x8e,
  // JNGE = 0x8c,
  // JNL = 0x8b,
  // JNLE = 0x8f,
  // JNP = 0x8b,
  // JNZ = 0x85,
  // JPE = 0x8a,
  // JPO = 0x8b,
};

enum cmp_kind {
  CMP_EQ,
  CMP_LT,
};

void emit_init();
void emit_cleanup();
int64_t emit_offset();
void emit_advance(int64_t offset);
void emit_bind(uint64_t label, uint64_t jmp);
void emit_check();
void emit_writable_begin();
void emit_writable_end();

void restore_callee_regs();
void save_callee_regs();

void emit_ret();
void emit_jmp32(int32_t offset);
void emit_jmp_abs(enum registers r);
void emit_jmp_indirect(int32_t offset);
void emit_call_indirect(uint8_t r);
void emit_call_indirect_mem(int32_t offset);
void emit_call32(int32_t offset);
void emit_mov64(uint8_t r, int64_t imm);
void emit_pop(uint8_t r);
void emit_push(uint8_t r);
void emit_mem_reg(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2);
void emit_mem_reg2(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2);
void emit_mem_reg_sib(uint8_t opcode, int32_t offset, uint8_t scale,
                      uint8_t index, uint8_t base, uint8_t reg);
void emit_mem_reg_sib2(uint8_t opcode, int32_t offset, uint8_t scale,
                       uint8_t index, uint8_t base, uint8_t reg);
void emit_mem_load(int32_t offset, uint8_t base, uint8_t dst);
void emit_store(int32_t offset, uint8_t base, uint8_t src);
void emit_store_constant(int32_t offset, uint8_t base, int64_t value);
void emit_rex(uint8_t w, uint8_t r, uint8_t x, uint8_t b);
void emit_imm8(uint8_t imm);
void emit_imm32(int32_t imm);
void emit_reg_reg(uint8_t opcode, uint8_t src, uint8_t dst);
void emit_reg_reg2(uint8_t opcode, uint8_t src, uint8_t dst);
void emit_jcc32(enum jcc_cond cond, int64_t offset);
void emit_op_imm32(uint8_t opcode, uint8_t r1, uint8_t r2, int32_t imm);
void emit_cmp_reg_imm32(uint8_t r, int32_t imm);
void emit_cmp_mem32_imm32(int32_t offset, uint8_t r1, int32_t imm);
void emit_arith_imm(enum ARITH_CODES op, uint8_t src, int32_t imm);
void emit_cmp(enum cmp_kind kind, uint8_t lhs, uint8_t rhs);
void emit_cmp_constant(enum cmp_kind kind, uint8_t reg, int64_t imm);
void emit_add(uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_add_constant(uint8_t dst, uint8_t lhs, int64_t imm);
void emit_sub(uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_sub_constant(uint8_t dst, uint8_t lhs, int64_t imm);

extern const char *const reg_names[MAX_REG];
