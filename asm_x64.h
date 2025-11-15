// Copyright 2023 Dave Watson

#pragma once

#include <stdint.h>

#define ASM_X64_REGISTER_LIST(X)                                               \
  X(RAX)                                                                       \
  X(RCX)                                                                       \
  X(RDX)                                                                       \
  X(RBX)                                                                       \
  X(RSP)                                                                       \
  X(RBP)                                                                       \
  X(RSI)                                                                       \
  X(RDI)                                                                       \
  X(R8)                                                                        \
  X(R9)                                                                        \
  X(R10)                                                                       \
  X(R11)                                                                       \
  X(R12)                                                                       \
  X(R13)                                                                       \
  X(R14)                                                                       \
  X(R15)

enum registers : uint8_t {
#define X(name) name,
  ASM_X64_REGISTER_LIST(X)
#undef X
      X64_MAX_REG,

  RET_REG = RAX,
  RET_REG2 = RDX,
  RARG0 = RDI,
  RARG1 = RSI,
  RARG2 = RDX,
  RARG3 = RCX,
  RARG4 = R8,
  RARG5 = R9,

  RTMP = R15,
  // Must be callee-save.
  RSTACK = R12,
};

_Static_assert(X64_MAX_REG < MAX_REG, "X64_MAX_REG must be less than MAX_REG");

void asm_mark_unallocatable(bool used[MAX_REG]);

enum ARITH_CODES {
  ASM_ARITH_ADD = 0,
  ASM_ARITH_SUB = 5,
  ASM_ARITH_CMP = 7,
  ASM_ARITH_NONE = 255,
};

enum OPCODES {
  ASM_ADD = 0x03,
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
  ASM_CMP = 0x3b,
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

void restore_callee_regs(emit_state *s);
void save_callee_regs(emit_state *s);

void emit_ret(emit_state *s);
void emit_jmp32(emit_state *s, int64_t target);
void emit_jmp32_patch_here(emit_state *s, int64_t patch);
void emit_mov64(emit_state *s, uint8_t r, int64_t imm);
void emit_mem_load(emit_state *s, int32_t offset, uint8_t base, uint8_t dst);
void emit_store(emit_state *s, int32_t offset, uint8_t base, uint8_t src);
void emit_store_constant(emit_state *s, int32_t offset, uint8_t base,
                         int64_t value);
void emit_jcc32(emit_state *s, enum jcc_cond cond, int64_t offset);
void emit_cmp(emit_state *s, uint8_t lhs, uint8_t rhs);
void emit_cmp_constant(emit_state *s, uint8_t reg, int64_t imm);
void emit_add(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_add_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm);
void emit_sub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_sub_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm);
void emit_mov(emit_state *s, uint8_t dst, uint8_t src);

extern const char *const reg_names[X64_MAX_REG];
