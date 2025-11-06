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

enum jcc_cond {
  JO = 0x6,  // VS
  JNO = 0x7, // VC
  JB = 0x3,  // LO/CC
  JAE = 0x2, // HS/CS
  JE = 0x0,  // EQ
  JNE = 0x1, // NE
  JBE = 0x9, // LS
  JA = 0x8,  // HI
  JS = 0x4,  // MI
  JNS = 0x5, // PL
  JL = 0xb,  // LT
  JGE = 0xa, // GE
  JLE = 0xd, // LE
  JG = 0xc,  // GT
  JP = 0xff, // Not supported on AArch64; keep sentinel for abort.
};

enum cmp_kind {
  CMP_EQ,
  CMP_LT,
};

void restore_callee_regs();
void save_callee_regs();

void emit_ret();
void emit_jmp32(int32_t offset);
void emit_jmp32_patch_here(int64_t patch);
void emit_mov64(uint8_t r, int64_t imm);
void emit_mem_load(int32_t offset, uint8_t base, uint8_t dst);
void emit_store(int32_t offset, uint8_t base, uint8_t src);
void emit_store_constant(int32_t offset, uint8_t base, int64_t value);
void emit_jcc32(enum jcc_cond cond, int64_t offset);
void emit_cmp(enum cmp_kind kind, uint8_t lhs, uint8_t rhs);
void emit_cmp_constant(enum cmp_kind kind, uint8_t reg, int64_t imm);
void emit_add(uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_add_constant(uint8_t dst, uint8_t lhs, int64_t imm);
void emit_sub(uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_sub_constant(uint8_t dst, uint8_t lhs, int64_t imm);

extern const char *const reg_names[MAX_REG];
