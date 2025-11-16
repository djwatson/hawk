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
      AARCH64_MAX_REG,

  RET_REG = X0,
  RET_REG2 = X1,
  RARG0 = X0,
  RTMP = X7,
  FP = X29,
  LR = X30,
  // In AArch64, register 31 is XZR (zero register) in most contexts,
  // but it is interpreted as SP (stack pointer) in some instructions,
  // particularly for memory access. We use SP as an alias for XZR
  // to represent register 31.
  SP = XZR,
  // Must be callee-save
  RSTACK = X25,
  RSATE = X26,
};

static_assert(AARCH64_MAX_REG <= MAX_REG,
              "AARCH64_MAX_REG must be less than MAX_REG");

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

extern const char *const reg_names[AARCH64_MAX_REG];
