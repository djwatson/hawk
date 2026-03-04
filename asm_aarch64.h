// Copyright 2024 Dave Watson

#pragma once

#include <stddef.h>
#include <stdint.h>
#include "asm_interface.h"

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

#define ASM_AARCH64_FREGISTER_LIST(X)                                          \
  X(V0)                                                                        \
  X(V1)                                                                        \
  X(V2)                                                                        \
  X(V3)                                                                        \
  X(V4)                                                                        \
  X(V5)                                                                        \
  X(V6)                                                                        \
  X(V7)                                                                        \
  X(V8)                                                                        \
  X(V9)                                                                        \
  X(V10)                                                                       \
  X(V11)                                                                       \
  X(V12)                                                                       \
  X(V13)                                                                       \
  X(V14)                                                                       \
  X(V15)                                                                       \
  X(V16)                                                                       \
  X(V17)                                                                       \
  X(V18)                                                                       \
  X(V19)                                                                       \
  X(V20)                                                                       \
  X(V21)                                                                       \
  X(V22)                                                                       \
  X(V23)                                                                       \
  X(V24)                                                                       \
  X(V25)                                                                       \
  X(V26)                                                                       \
  X(V27)                                                                       \
  X(V28)                                                                       \
  X(V29)                                                                       \
  X(V30)                                                                       \
  X(V31)

enum registers : uint8_t {
#define X(name) name,
  ASM_AARCH64_REGISTER_LIST(X)
#undef X
#define X(name) name,
      ASM_AARCH64_FREGISTER_LIST(X)
#undef X
          AARCH64_MAX_REG,

  RET_REG = X0,
  RET_REG2 = X1,
  RARG0 = X0,
  RARG1 = X1,
  RARG2 = X2,
  RARG3 = X3,
  RARG4 = X4,
  RARG5 = X5,
  RARG6 = X6,
  RARG7 = X7,
  RTMP = X7,
  RTMP2 = X8,
  FP = X29,
  LR = X30,
  // In AArch64, register 31 is XZR (zero register) in most contexts,
  // but it is interpreted as SP (stack pointer) in some instructions,
  // particularly for memory access. We use SP as an alias for XZR
  // to represent register 31.
  SP = XZR,
  // Must be callee-save
  RSTACK = X25,
  RSTATE = X26,
};

enum { FPR_REG_START = V0 };
enum { AARCH64_GPR_COUNT = FPR_REG_START };
enum { AARCH64_FPR_COUNT = AARCH64_MAX_REG - FPR_REG_START };
enum { FPR_REG_END = AARCH64_MAX_REG };

static_assert(AARCH64_MAX_REG <= MAX_REG,
              "AARCH64_MAX_REG must be less than MAX_REG");
enum : uint8_t {
  FRTMP = V31,
};

void asm_mark_unallocatable(bool used[MAX_REG]);
bool asm_is_callee_saved(uint8_t reg);

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
  JP = 0x6,  // VS (used for floating-point unordered).
};

extern const char *const reg_names[AARCH64_MAX_REG];
