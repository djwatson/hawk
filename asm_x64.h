// Copyright 2023 Dave Watson

#pragma once

#include "asm_interface.h"
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#define ASM_X64_REGISTER_LIST(X)                                               \
  X(RAX, false, false)                                                         \
  X(RCX, false, false)                                                         \
  X(RDX, false, false)                                                         \
  X(RBX, true, true)                                                           \
  X(RSP, true, false)                                                          \
  X(RBP, false, true)                                                          \
  X(RSI, false, false)                                                         \
  X(RDI, false, false)                                                         \
  X(R8, false, false)                                                          \
  X(R9, false, false)                                                          \
  X(R10, false, false)                                                         \
  X(R11, false, false)                                                         \
  X(R12, true, true)                                                           \
  X(R13, true, true)                                                           \
  X(R14, true, true)                                                           \
  X(R15, true, true)

#define ASM_X64_FREGISTER_LIST(X)                                              \
  X(XMM0, false, false)                                                        \
  X(XMM1, false, false)                                                        \
  X(XMM2, false, false)                                                        \
  X(XMM3, false, false)                                                        \
  X(XMM4, false, false)                                                        \
  X(XMM5, false, false)                                                        \
  X(XMM6, false, false)                                                        \
  X(XMM7, false, false)                                                        \
  X(XMM8, false, false)                                                        \
  X(XMM9, false, false)                                                        \
  X(XMM10, false, false)                                                       \
  X(XMM11, false, false)                                                       \
  X(XMM12, false, false)                                                       \
  X(XMM13, false, false)                                                       \
  X(XMM14, false, false)                                                       \
  X(XMM15, true, false)

#define ASM_REGISTER_LIST(X) ASM_X64_REGISTER_LIST(X)
#define ASM_FREGISTER_LIST(X) ASM_X64_FREGISTER_LIST(X)

enum {
#define X(name, unallocatable, callee_saved) + (!(unallocatable))
  GPR_ALLOCATABLE = 0 ASM_X64_REGISTER_LIST(X),
#undef X
#define X(name, unallocatable, callee_saved) + (!(unallocatable))
  FPR_ALLOCATABLE = 0 ASM_X64_FREGISTER_LIST(X),
#undef X
};

enum registers : uint8_t {
#define X(name, unallocatable, callee_saved) name,
  ASM_X64_REGISTER_LIST(X)
#undef X
#define X(name, unallocatable, callee_saved) name,
      ASM_X64_FREGISTER_LIST(X)
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
  SP = RSP,

  RALLOC = RBX,
  RTMP2 = R14,
  RTMP = R15,
  // Must be callee-save.
  RSTACK = R12,
  RSTATE = R13,
};

enum { FPR_REG_START = XMM0 };
enum { X64_GPR_COUNT = FPR_REG_START };
enum { X64_FPR_COUNT = X64_MAX_REG - FPR_REG_START };
enum { FPR_REG_END = X64_MAX_REG };

_Static_assert(X64_MAX_REG <= MAX_REG, "X64_MAX_REG must be less than MAX_REG");
enum : uint8_t {
  FRTMP = XMM15,
};

enum ARITH_CODES {
  ASM_ARITH_ADD = 0,
  ASM_ARITH_SUB = 5,
  ASM_ARITH_CMP = 7,
  ASM_ARITH_NONE = 255,
};

enum OPCODES {
  ASM_ADD = 0x03,
  ASM_SUB = 0x2b,
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

extern const char *const reg_names[FPR_REG_END];

static inline uint8_t asm_foreign_call_max_gpr_args(void) { return 6; }
static inline uint8_t asm_foreign_call_max_fpr_args(void) { return 8; }

static inline uint8_t asm_foreign_call_arg_gpr(uint8_t idx) {
  static const uint8_t regs[] = {RARG0, RARG1, RARG2, RARG3, RARG4, RARG5};
  if (idx >= sizeof(regs)) {
    abort();
  }
  return regs[idx];
}

static inline uint8_t asm_foreign_call_arg_fpr(uint8_t idx) {
  uint8_t reg = (uint8_t)(FPR_REG_START + idx);
  if (reg > XMM7) {
    abort();
  }
  return reg;
}

static inline uint8_t asm_foreign_call_ret_fpr(void) { return XMM0; }
