// Copyright 2023 Dave Watson

#define _DEFAULT_SOURCE

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "asm.h"
#include "hawk.h"

static void emit_reg_reg(emit_state *s, uint8_t opcode, uint8_t src,
                         uint8_t dst);

static inline uint8_t hw_fpr(uint8_t reg) {
  assert(reg >= FPR_REG_START && reg < X64_MAX_REG);
  return reg - FPR_REG_START;
}

const char *const reg_names[X64_MAX_REG] = {
#define X(name) #name,
    ASM_X64_REGISTER_LIST(X)
#undef X
#define X(name) #name,
        ASM_X64_FREGISTER_LIST(X)
#undef X
};

void asm_mark_unallocatable(bool used[MAX_REG]) {
  used[RSP] = true;
  used[RTMP] = true;
  used[RSTACK] = true;
  used[RSTATE] = true;
}

bool asm_is_callee_saved(uint8_t reg) {
  switch (reg) {
  case RBX:
  case RBP:
  case R12:
  case R13:
  case R14:
  case R15:
    return true;
  default:
    return false;
  }
}

static uint8_t low3bits(uint8_t r) { return 0x7 & r; }

/////////////////// instruction encoding

#define p (s->p)
static void emit_rex(emit_state *s, uint8_t w, uint8_t r, uint8_t x,
                     uint8_t b) {
  *(--p) = 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
}

static void emit_rex_optional(emit_state *s, uint8_t w, uint8_t r, uint8_t x,
                              uint8_t b) {
  if (w | r | x | b) {
    emit_rex(s, w, r, x, b);
  }
}

static void emit_modrm(emit_state *s, uint8_t mod, uint8_t reg, uint8_t rm) {
  *(--p) = (mod << 6) | (reg << 3) | rm;
}

static void emit_sib(emit_state *s, uint8_t scale, uint8_t index,
                     uint8_t base) {
  *(--p) = (scale << 6) | ((0x7 & index) << 3) | ((0x7 & base));
}

static void emit_imm8(emit_state *s, uint8_t imm) { *(--p) = imm; }

static void emit_imm64(emit_state *s, int64_t imm) {
  p -= sizeof(int64_t);
  memcpy(p, &imm, sizeof(imm));
}

static void emit_imm32(emit_state *s, int32_t imm) {
  p -= sizeof(int32_t);
  memcpy(p, &imm, sizeof(imm));
}

static bool fits_in_32(int64_t imm) { return imm == (int64_t)(int32_t)imm; }

static bool fits_in_u32(int64_t imm) {
  return imm >= 0 && imm <= (int64_t)UINT32_MAX;
}

void emit_mov64(emit_state *s, uint8_t r, int64_t imm) {
  assert(r < FPR_REG_START);
  // Note that 'imm' isn't necessarily a number here,
  // so we can't narrow negative numbers.
#ifndef VALGRIND
  if (!fits_in_u32(imm)) {
#endif
    emit_imm64(s, imm);
    *(--p) = 0xb8 | (0x7 & r);
    emit_rex(s, 1, 0, 0, r >> 3);
#ifndef VALGRIND
  } else {
    // Unfortunately valgrind doesn't like this:
    // We do *NOT* want to sign-extend here!
    emit_imm32(s, (int32_t)imm);
    *(--p) = 0xb8 | (0x7 & r);
    if (r >> 3) {
      emit_rex(s, 0, 0, 0, r >> 3);
    }
  }
#endif
}

static void emit_call_indirect(emit_state *s, uint8_t r) {
  emit_modrm(s, 0x3, 0x2, 0x7 & r);
  *(--p) = 0xff;
  emit_rex_optional(s, 0, 0, 0, r >> 3);
}

void emit_call_reg(emit_state *s, uint8_t r) { emit_call_indirect(s, r); }

static void emit_call_indirect_mem(emit_state *s, int32_t offset) {
  emit_imm32(s, offset);
  emit_modrm(s, 0x00, 2, RBP);
  *(--p) = 0xff;
  emit_rex_optional(s, 0, 0, 0, 0);
}

static void emit_call32_imm(emit_state *s, int32_t offset) {
  emit_imm32(s, offset);
  *(--p) = 0xe8;
}

void emit_call32(emit_state *s, int64_t target) {
  int64_t delta = target - emit_offset(s);
  assert(fits_in_32(delta));
  emit_call32_imm(s, (int32_t)delta);
}

void emit_ret(emit_state *s) { *(--p) = 0xc3; }

// TODO(djwatson) clean this up.  THe main issue is REX needs W=0.
// Also check R1 does full checks for rsp/rbp
static void emit_cmp_mem32_imm32(emit_state *s, int32_t offset, uint8_t r1,
                                 int32_t imm) {
  emit_imm32(s, imm);
  assert(r1 != RSP);
  assert(r1 != RBP);
  uint8_t r2 = 0x7;

  if (offset == 0 && low3bits(r1) != RBP) {
    emit_modrm(s, 0x0, r2, 0x7 & r1);
  } else if ((int32_t)((int8_t)offset) == offset) {
    *(--p) = (int8_t)offset;
    emit_modrm(s, 0x1, r2, 0x7 & r1);
  } else {
    emit_imm32(s, offset);
    emit_modrm(s, 0x2, r2, 0x7 & r1);
  }

  *(--p) = 0x81;
  emit_rex(s, 0, 0, 0, r1 >> 3);
}
static void emit_cmp_reg_imm32(emit_state *s, uint8_t r, int32_t imm) {
  if ((int32_t)((int8_t)imm) == imm) {
    *(--p) = imm;
    emit_reg_reg(s, 0x83, 7, r);
  } else {
    emit_imm32(s, imm);
    emit_reg_reg(s, 0x81, 7, r);
  }
}

static void emit_cmp_reg_reg(emit_state *s, uint8_t src, uint8_t dst) {
  emit_modrm(s, 0x3, 0x7 & src, 0x7 & dst);
  *(--p) = 0x3b;
  emit_rex(s, 1, src >> 3, 0, dst >> 3);
}

void emit_jcc32(emit_state *s, enum jcc_cond cond, int64_t offset) {
  int64_t off = offset - emit_offset(s);
  if ((int32_t)((int8_t)off) == off) {
    *(--p) = (int8_t)off;
    *(--p) = cond - 0x10;
  } else {
    assert(fits_in_32(off));
    emit_imm32(s, (int32_t)off);
    *(--p) = cond;
    *(--p) = 0x0f;
  }
}

void emit_jmp32(emit_state *s, int64_t target) {
  int64_t delta = target - emit_offset(s);
  assert(fits_in_32(delta));
  emit_imm32(s, (int32_t)delta);
  *(--p) = 0xe9;
}

static void emit_jmp_indirect(emit_state *s, int32_t offset) {
  emit_imm32(s, offset);
  emit_modrm(s, 0x0, 4, RBP);
  *(--p) = 0xff;
}

static void emit_jmp_abs(emit_state *s, enum registers r) {
  emit_modrm(s, 0x3, 4, 0x7 & r);
  *(--p) = 0xff;
  if (r >> 3) {
    emit_rex(s, 0, 0, 0, r >> 3);
  }
}

static void emit_reg_reg(emit_state *s, uint8_t opcode, uint8_t src,
                         uint8_t dst) {
  emit_modrm(s, 0x3, 0x7 & src, 0x7 & dst);
  *(--p) = opcode;
  emit_rex(s, 1, src >> 3, 0, dst >> 3);
}

static void emit_reg_reg2(emit_state *s, uint8_t opcode, uint8_t src,
                          uint8_t dst) {
  emit_modrm(s, 0x3, 0x7 & src, 0x7 & dst);
  *(--p) = opcode;
  *(--p) = 0x0f;
  emit_rex(s, 1, src >> 3, 0, dst >> 3);
}

static void emit_sse_reg_reg(emit_state *s, uint8_t prefix, uint8_t opcode,
                             uint8_t src, uint8_t dst) {
  emit_modrm(s, 0x3, 0x7 & src, 0x7 & dst);
  *(--p) = opcode;
  *(--p) = 0x0f;
  emit_rex_optional(s, 0, src >> 3, 0, dst >> 3);
  if (prefix) {
    *(--p) = prefix;
  }
}

static uint8_t *emit_sse_literal_instr(emit_state *s, uint8_t prefix,
                                       uint8_t opcode, uint8_t dst) {
  emit_imm32(s, 0);
  uint8_t *disp = p;
  emit_modrm(s, 0x0, 0x7 & dst, 0x5);
  *(--p) = opcode;
  *(--p) = 0x0f;
  emit_rex_optional(s, 0, dst >> 3, 0, 0);
  if (prefix) {
    *(--p) = prefix;
  }
  return disp;
}

static void emit_sse_literal_constant(emit_state *s, uint8_t prefix,
                                      uint8_t opcode, uint8_t dst, int idx) {
  assert(idx >= 0);
  assert((size_t)idx < arrlen(s->const_pool));
  constant_entry *entry = &s->const_pool[idx];
  uint8_t *disp = emit_sse_literal_instr(s, prefix, opcode, dst);
  const_patch patch = {.inst0 = disp, .inst1 = nullptr};
  arrput(&s->z, entry->patches, patch);
}

static void emit_mem_reg_sib(emit_state *s, uint8_t opcode, int32_t offset,
                             uint8_t scale, uint8_t index, uint8_t base,
                             uint8_t reg) {
  if ((int32_t)((int8_t)offset) == offset) {
    *(--p) = (int8_t)offset;
    emit_sib(s, scale, index, base);
    emit_modrm(s, 0x1, 0x7 & reg, 0x4);
  } else {
    emit_imm32(s, offset);
    emit_sib(s, scale, index, base);
    emit_modrm(s, 0x2, 0x7 & reg, 0x4);
  }
  *(--p) = opcode;
  emit_rex(s, 1, reg >> 3, index >> 3, base >> 3);
}

static void emit_mem_reg_sib2(emit_state *s, uint8_t opcode, int32_t offset,
                              uint8_t scale, uint8_t index, uint8_t base,
                              uint8_t reg) {
  if ((int32_t)((int8_t)offset) == offset) {
    *(--p) = (int8_t)offset;
    emit_sib(s, scale, index, base);
    emit_modrm(s, 0x1, 0x7 & reg, 0x4);
  } else {
    emit_imm32(s, offset);
    emit_sib(s, scale, index, base);
    emit_modrm(s, 0x2, 0x7 & reg, 0x4);
  }
  *(--p) = opcode;
  *(--p) = 0xf;
  emit_rex(s, 1, reg >> 3, index >> 3, base >> 3);
}

static void emit_mem_reg(emit_state *s, uint8_t opcode, int32_t offset,
                         uint8_t r1, uint8_t r2) {
  if (low3bits(r1) == RSP) {
    emit_mem_reg_sib(s, opcode, offset, 0, RSP, r1, r2);
  } else {
    if (offset == 0 && low3bits(r1) != RBP) {
      emit_modrm(s, 0x0, 0x7 & r2, 0x7 & r1);
    } else if ((int32_t)((int8_t)offset) == offset) {
      *(--p) = (int8_t)offset;
      emit_modrm(s, 0x1, 0x7 & r2, 0x7 & r1);
    } else {
      emit_imm32(s, offset);
      emit_modrm(s, 0x2, 0x7 & r2, 0x7 & r1);
    }
    *(--p) = opcode;
    emit_rex(s, 1, r2 >> 3, 0, r1 >> 3);
  }
}

static void emit_sse_mem(emit_state *s, uint8_t prefix, uint8_t opcode,
                         int32_t offset, uint8_t base, uint8_t freg) {
  if (low3bits(base) == RSP) {
    if ((int32_t)((int8_t)offset) == offset) {
      *(--p) = (int8_t)offset;
      emit_sib(s, 0, RSP, base);
      emit_modrm(s, 0x1, 0x7 & freg, 0x4);
    } else {
      emit_imm32(s, offset);
      emit_sib(s, 0, RSP, base);
      emit_modrm(s, 0x2, 0x7 & freg, 0x4);
    }
  } else {
    if (offset == 0 && low3bits(base) != RBP) {
      emit_modrm(s, 0x0, 0x7 & freg, 0x7 & base);
    } else if ((int32_t)((int8_t)offset) == offset) {
      *(--p) = (int8_t)offset;
      emit_modrm(s, 0x1, 0x7 & freg, 0x7 & base);
    } else {
      emit_imm32(s, offset);
      emit_modrm(s, 0x2, 0x7 & freg, 0x7 & base);
    }
  }
  *(--p) = opcode;
  *(--p) = 0x0f;
  emit_rex_optional(s, 0, freg >> 3, 0, base >> 3);
  if (prefix) {
    *(--p) = prefix;
  }
}

void emit_mem_load(emit_state *s, int32_t offset, uint8_t base, uint8_t dst) {
  assert(dst < MAX_REG);
  emit_mem_reg(s, ASM_MOV_MR, offset, base, dst);
}

void emit_fmem_load(emit_state *s, int32_t offset, uint8_t base, uint8_t dst) {
  assert(dst >= FPR_REG_START && dst < X64_MAX_REG);
  assert(base < FPR_REG_START);
  emit_sse_mem(s, 0xF2, 0x10, offset, base, hw_fpr(dst));
}

// TODO(djwatson) merge the '2' byte versions
static void emit_mem_reg2(emit_state *s, uint8_t opcode, int32_t offset,
                          uint8_t r1, uint8_t r2) {
  if (low3bits(r1) == RSP) {
    emit_mem_reg_sib2(s, opcode, offset, 0, RSP, r1, r2);
  } else {
    if ((int32_t)((int8_t)offset) == offset) {
      *(--p) = (int8_t)offset;
      emit_modrm(s, 0x1, 0x7 & r2, 0x7 & r1);
    } else {
      emit_imm32(s, offset);
      emit_modrm(s, 0x2, 0x7 & r2, 0x7 & r1);
    }
    *(--p) = opcode;
    *(--p) = 0xF;
    emit_rex(s, 1, r2 >> 3, 0, r1 >> 3);
  }
}

/////////////////// opcodes

static void emit_op_imm32(emit_state *s, uint8_t opcode, uint8_t r1, uint8_t r2,
                          int32_t imm) {
  emit_imm32(s, imm);
  emit_reg_reg(s, opcode, r1, r2);
}

static void emit_arith_imm(emit_state *s, enum ARITH_CODES op, uint8_t src,
                           int32_t imm) {
  if ((int32_t)((int8_t)imm) == imm) {
    *(--p) = imm;
    emit_reg_reg(s, 0x83, op, src);
  } else {
    emit_imm32(s, imm);
    emit_reg_reg(s, 0x81, op, src);
  }
}

static void emit_neg(emit_state *s, uint8_t r) {
  *(--p) = 0xf7 + (0x7 & r);
  if (r >> 3) {
    emit_rex(s, 0, 0, 0, r >> 3);
  }
}
static void emit_fneg(emit_state *s, uint8_t r) {
  assert(r >= FPR_REG_START && r < X64_MAX_REG);
  uint8_t hw = hw_fpr(r);
  int idx = add_constant(s, -0.0);
  constant_entry *entry = &s->const_pool[idx];

  emit_imm32(s, 0);
  uint8_t *disp = p;
  emit_modrm(s, 0x0, 0x7 & hw, 0x5);
  *(--p) = 0x57;
  *(--p) = 0x0f;
  emit_rex_optional(s, 0, hw >> 3, 0, 0);
  *(--p) = 0x66;

  const_patch patch = {.inst0 = disp, .inst1 = nullptr};
  arrput(&s->z, entry->patches, patch);
}

void emit_push(emit_state *s, uint8_t r) {
  *(--p) = 0x50 + (0x7 & r);
  emit_rex_optional(s, 0, 0, 0, r >> 3);
}

void emit_pop(emit_state *s, uint8_t r) {
  *(--p) = 0x58 | (0x7 & r);
  emit_rex_optional(s, 0, 0, 0, r >> 3);
}

void emit_debugtrap(emit_state *s) { *(--p) = 0xcc; }

void emit_push_regs(emit_state *s, uint8_t const *regs, size_t count,
                    bool abi) {
  bool odd = (count + abi) & 1;
  for (size_t i = 0; i < count; i++) {
    uint8_t reg = regs[i];
    if (reg >= FPR_REG_START) {
      emit_fstore(s, 0, RSP, reg);
      emit_sub_constant(s, RSP, RSP, 16);
    } else {
      emit_push(s, reg);
    }
  }
  if (odd) {
    emit_sub_constant(s, RSP, RSP, 8);
  }
}

void emit_pop_regs(emit_state *s, uint8_t const *regs, size_t count, bool abi) {
  bool odd = (count + abi) & 1;
  if (odd) {
    emit_add_constant(s, RSP, RSP, 8);
  }
  for (size_t i = count; i > 0; i--) {
    uint8_t reg = regs[i - 1];
    if (reg >= FPR_REG_START) {
      emit_add_constant(s, RSP, RSP, 16);
      emit_fmem_load(s, 0, RSP, reg);
    } else {
      emit_pop(s, reg);
    }
  }
}

static void emit_cmovl(emit_state *s, uint8_t dst, uint8_t src) {
  emit_modrm(s, 0x3, 0x7 & src, 0x7 & dst);
  *(--p) = 0x4c;
  *(--p) = 0x0f;
  emit_rex(s, 1, src >> 3, 0, dst >> 3);
}

void emit_mov(emit_state *s, uint8_t dst, uint8_t src) {
  if (dst == src) {
    return;
  }
  emit_reg_reg(s, ASM_MOV_MR, dst, src);
}
void emit_cmp(emit_state *s, uint8_t lhs, uint8_t rhs) {
  assert(lhs < FPR_REG_START);
  assert(rhs < FPR_REG_START);
  emit_reg_reg(s, ASM_CMP, lhs, rhs);
}
void emit_fcmp(emit_state *s, uint8_t lhs, uint8_t rhs) {
  emit_sse_reg_reg(s, 0x66, 0x2E, hw_fpr(lhs), hw_fpr(rhs));
}
void emit_fcmp_constant(emit_state *s, uint8_t reg, double imm) {
  int idx = add_constant(s, imm);
  emit_sse_literal_constant(s, 0x66, 0x2E, hw_fpr(reg), idx);
}

void emit_fmov_constant(emit_state *s, uint8_t dst, double imm) {
  int idx = add_constant(s, imm);
  load_constant(s, idx, dst);
}
void emit_fmov(emit_state *s, uint8_t dst, uint8_t src) {
  emit_sse_reg_reg(s, 0xF2, 0x10, hw_fpr(dst), hw_fpr(src));
}
void emit_cmp_constant(emit_state *s, uint8_t reg, int64_t imm) {
  assert(reg < FPR_REG_START);
  if (fits_in_32(imm)) {
    emit_cmp_reg_imm32(s, reg, (int32_t)imm);
  } else {
    emit_cmp(s, reg, RTMP);
    emit_mov64(s, RTMP, imm);
  }
}

void emit_test_constant(emit_state *s, uint8_t reg, int64_t imm) {
  assert(reg < FPR_REG_START);
  if (!fits_in_32(imm)) {
    abort();
  }
  emit_imm32(s, (int32_t)imm);
  emit_reg_reg(s, ASM_TEST_IMM, 0, reg);
}

void emit_add(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  if (dst == lhs) {
    emit_reg_reg(s, ASM_ADD, lhs, rhs);
  } else if (rhs == dst) {
    emit_reg_reg(s, ASM_ADD, dst, lhs);
  } else {
    emit_reg_reg(s, ASM_ADD, dst, rhs);
    emit_mov(s, dst, lhs);
  }
}
static void emit_add_sub_constant(emit_state *s, enum ARITH_CODES op,
                                  uint8_t dst, uint8_t lhs, int64_t imm) {
  if (fits_in_32(imm)) {
    emit_arith_imm(s, op, dst, (int32_t)imm);
    if (dst != lhs) {
      emit_mov(s, dst, lhs);
    }
    return;
  }

  if (op == ASM_ARITH_ADD) {
    emit_add(s, dst, lhs, RTMP);
  } else {
    emit_sub(s, dst, lhs, RTMP);
  }
  emit_mov64(s, RTMP, imm);
}

// Slightly different from emit_add, since we need to negate if reversed.
void emit_sub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  if (dst == lhs) {
    emit_reg_reg(s, ASM_SUB, lhs, rhs);
  } else if (rhs == dst) {
    emit_neg(s, dst);
    emit_reg_reg(s, ASM_SUB, dst, lhs);
  } else {
    emit_reg_reg(s, ASM_SUB, dst, rhs);
    emit_mov(s, dst, lhs);
  }
}
void emit_fadd(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  if (dst == lhs) {
    emit_sse_reg_reg(s, 0xF2, 0x58, hw_fpr(lhs), hw_fpr(rhs));
  } else if (rhs == dst) {
    emit_sse_reg_reg(s, 0xF2, 0x58, hw_fpr(dst), hw_fpr(lhs));
  } else {
    emit_sse_reg_reg(s, 0xF2, 0x58, hw_fpr(dst), hw_fpr(rhs));
    emit_fmov(s, dst, lhs);
  }
}

void emit_fsub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  if (dst == lhs) {
    emit_sse_reg_reg(s, 0xF2, 0x5C, hw_fpr(lhs), hw_fpr(rhs));
  } else if (rhs == dst) {
    emit_fneg(s, dst);
    emit_sse_reg_reg(s, 0xF2, 0x5C, hw_fpr(dst), hw_fpr(lhs));
  } else {
    emit_sse_reg_reg(s, 0xF2, 0x5C, hw_fpr(dst), hw_fpr(rhs));
    emit_fmov(s, dst, lhs);
  }
}

void emit_fadd_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  int idx = add_constant(s, imm);
  emit_sse_literal_constant(s, 0xF2, 0x58, hw_fpr(dst), idx);
  if (dst != lhs) {
    emit_fmov(s, dst, lhs);
  }
}

void emit_fsub_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  int idx = add_constant(s, imm);
  emit_sse_literal_constant(s, 0xF2, 0x5C, hw_fpr(dst), idx);
  if (dst != lhs) {
    emit_fmov(s, dst, lhs);
  }
}
void emit_add_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm) {
  emit_add_sub_constant(s, ASM_ARITH_ADD, dst, lhs, imm);
}
void emit_sub_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm) {
  emit_add_sub_constant(s, ASM_ARITH_SUB, dst, lhs, imm);
}
void emit_store(emit_state *s, int32_t offset, uint8_t base, uint8_t src) {
  emit_mem_reg(s, ASM_MOV_RM, offset, base, src);
}

void emit_fstore(emit_state *s, int32_t offset, uint8_t base, uint8_t src) {
  assert(src >= FPR_REG_START && src < X64_MAX_REG);
  assert(base < FPR_REG_START);
  emit_sse_mem(s, 0xF2, 0x11, offset, base, hw_fpr(src));
}
void emit_store_constant(emit_state *s, int32_t offset, uint8_t base,
                         int64_t value) {
  emit_store(s, offset, base, RTMP);
  emit_mov64(s, RTMP, value);
}
void emit_jmp32_patch_here(emit_state *s, int64_t patch) {
  assert(patch);
  int64_t target = emit_offset(s);
  int64_t delta = target - patch - 5;
  assert(fits_in_32(delta));
  uint8_t jmp = 0xe9;
  memcpy((uint8_t *)patch, &jmp, 1);
  memcpy((uint8_t *)patch + 1, &delta, 4);
}

/////////////////// memory

// Emit R15 twice, so we have an odd number - and therefore a balanced stack
uint8_t callee_save[] = {RBX, RBP, R12, R13, R14, R15, R15};
void restore_callee_regs(emit_state *s) {
  for (size_t i = 0; i < ARRAY_LEN(callee_save); i++) {
    emit_pop(s, callee_save[i]);
  }
}
void save_callee_regs(emit_state *s) {
  for (size_t i = ARRAY_LEN(callee_save); i > 0; i--) {
    emit_push(s, callee_save[i - 1]);
  }
}

void asm_load_constant(emit_state *s, int idx, uint8_t dst) {
  assert(dst >= FPR_REG_START && dst < X64_MAX_REG);
  assert(idx >= 0);
  assert((size_t)idx < arrlen(s->const_pool));
  emit_sse_literal_constant(s, 0xF2, 0x10, hw_fpr(dst), idx);
}

void asm_patch_constant_pool(emit_state *s) {
  size_t len = arrlen(s->const_pool);
  for (size_t i = 0; i < len; i++) {
    constant_entry *entry = &s->const_pool[i];
    size_t patch_len = arrlen(entry->patches);
    for (size_t j = 0; j < patch_len; j++) {
      uint8_t *disp = entry->patches[j].inst0;
      assert(disp);
      int64_t delta =
          (int64_t)(entry->addr - (disp + (ptrdiff_t)sizeof(int32_t)));
      assert(delta >= INT32_MIN && delta <= INT32_MAX);
      int32_t rel = (int32_t)delta;
      memcpy(disp, &rel, sizeof(rel));
    }
  }
}
