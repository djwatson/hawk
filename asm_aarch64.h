// Copyright 2024 Dave Watson

#pragma once

#include "asm_interface.h"
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

#define ASM_AARCH64_REGISTER_LIST(X)                                           \
  X(X0, false, false)                                                          \
  X(X1, false, false)                                                          \
  X(X2, false, false)                                                          \
  X(X3, false, false)                                                          \
  X(X4, false, false)                                                          \
  X(X5, false, false)                                                          \
  X(X6, false, false)                                                          \
  X(X7, true, false)                                                           \
  X(X8, true, false)                                                           \
  X(X9, false, false)                                                          \
  X(X10, false, false)                                                         \
  X(X11, false, false)                                                         \
  X(X12, false, false)                                                         \
  X(X13, false, false)                                                         \
  X(X14, false, false)                                                         \
  X(X15, false, false)                                                         \
  X(X16, true, false)                                                          \
  X(X17, true, false)                                                          \
  X(X18, true, false)                                                          \
  X(X19, false, true)                                                          \
  X(X20, false, true)                                                          \
  X(X21, false, true)                                                          \
  X(X22, false, true)                                                          \
  X(X23, false, true)                                                          \
  X(X24, false, true)                                                          \
  X(X25, true, true)                                                           \
  X(X26, true, true)                                                           \
  X(X27, true, true)                                                           \
  X(X28, false, true)                                                          \
  X(X29, true, true)                                                           \
  X(X30, true, true)                                                           \
  X(XZR, true, false)

#define ASM_AARCH64_FREGISTER_LIST(X)                                          \
  X(V0, false, false)                                                          \
  X(V1, false, false)                                                          \
  X(V2, false, false)                                                          \
  X(V3, false, false)                                                          \
  X(V4, false, false)                                                          \
  X(V5, false, false)                                                          \
  X(V6, false, false)                                                          \
  X(V7, false, false)                                                          \
  X(V8, false, true)                                                           \
  X(V9, false, true)                                                           \
  X(V10, false, true)                                                          \
  X(V11, false, true)                                                          \
  X(V12, false, true)                                                          \
  X(V13, false, true)                                                          \
  X(V14, false, true)                                                          \
  X(V15, false, true)                                                          \
  X(V16, false, false)                                                         \
  X(V17, false, false)                                                         \
  X(V18, false, false)                                                         \
  X(V19, false, false)                                                         \
  X(V20, false, false)                                                         \
  X(V21, false, false)                                                         \
  X(V22, false, false)                                                         \
  X(V23, false, false)                                                         \
  X(V24, false, false)                                                         \
  X(V25, false, false)                                                         \
  X(V26, false, false)                                                         \
  X(V27, false, false)                                                         \
  X(V28, false, false)                                                         \
  X(V29, false, false)                                                         \
  X(V30, false, false)                                                         \
  X(V31, true, false)

#define ASM_REGISTER_LIST(X) ASM_AARCH64_REGISTER_LIST(X)
#define ASM_FREGISTER_LIST(X) ASM_AARCH64_FREGISTER_LIST(X)

enum {
#define X(name, unallocatable, callee_saved) + (!(unallocatable))
  GPR_ALLOCATABLE = 0 ASM_AARCH64_REGISTER_LIST(X),
#undef X
#define X(name, unallocatable, callee_saved) + (!(unallocatable))
  FPR_ALLOCATABLE = 0 ASM_AARCH64_FREGISTER_LIST(X),
#undef X
};

enum registers : uint8_t {
#define X(name, unallocatable, callee_saved) name,
  ASM_AARCH64_REGISTER_LIST(X)
#undef X
#define X(name, unallocatable, callee_saved) name,
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
  RALLOC = X27,
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

extern const char *const reg_names[FPR_REG_END];

static inline uint8_t asm_foreign_call_max_gpr_args(void) { return 8; }
static inline uint8_t asm_foreign_call_max_fpr_args(void) { return 8; }

static inline uint8_t asm_foreign_call_arg_gpr(uint8_t idx) {
  static const uint8_t regs[] = {RARG0, RARG1, RARG2, RARG3,
                                 RARG4, RARG5, RARG6, RARG7};
  if (idx >= sizeof(regs)) {
    abort();
  }
  return regs[idx];
}

static inline uint8_t asm_foreign_call_arg_fpr(uint8_t idx) {
  uint8_t reg = (uint8_t)(FPR_REG_START + idx);
  if (reg > V7) {
    abort();
  }
  return reg;
}

static inline uint8_t asm_foreign_call_ret_fpr(void) { return V0; }
