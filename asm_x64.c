// Copyright 2023 Dave Watson

#define _DEFAULT_SOURCE

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
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

static void emit_rex(emit_state *s, uint8_t w, uint8_t r, uint8_t x,
                     uint8_t b) {
  emit_byte(s, 0x40 | (w << 3) | (r << 2) | (x << 1) | b);
}

static void emit_rex_optional(emit_state *s, uint8_t w, uint8_t r, uint8_t x,
                              uint8_t b) {
  if (w | r | x | b) {
    emit_rex(s, w, r, x, b);
  }
}

static void emit_modrm(emit_state *s, uint8_t mod, uint8_t reg, uint8_t rm) {
  emit_byte(s, (mod << 6) | (reg << 3) | rm);
}

static void emit_sib(emit_state *s, uint8_t scale, uint8_t index,
                     uint8_t base) {
  emit_byte(s, (scale << 6) | ((0x7 & index) << 3) | (0x7 & base));
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
    emit_rex(s, 1, 0, 0, r >> 3);
    emit_byte(s, 0xb8 | (0x7 & r));
    emit_imm64(s, (uint64_t)imm);
#ifndef VALGRIND
  } else {
    // Unfortunately valgrind doesn't like this:
    // We do *NOT* want to sign-extend here!
    emit_rex_optional(s, 0, 0, 0, r >> 3);
    emit_byte(s, 0xb8 | (0x7 & r));
    emit_imm32(s, (uint32_t)imm);
  }
#endif
}

static void emit_call_indirect(emit_state *s, uint8_t r) {
  emit_rex_optional(s, 0, 0, 0, r >> 3);
  emit_byte(s, 0xff);
  emit_modrm(s, 0x3, 0x2, 0x7 & r);
}

void emit_call_reg(emit_state *s, uint8_t r) { emit_call_indirect(s, r); }

static void emit_call32_imm(emit_state *s, int32_t offset) {
  emit_byte(s, 0xe8);
  emit_imm32(s, (uint32_t)offset);
}

void emit_call32(emit_state *s, int64_t target) {
  int64_t delta = target - (emit_offset(s) + 5);
  assert(fits_in_32(delta));
  emit_call32_imm(s, (int32_t)delta);
}

void emit_ret(emit_state *s) { emit_byte(s, 0xc3); }

void asm_patch_jmp32(emit_state *s, uint8_t *loc, uint8_t *target) {
  (void)s;
  assert(loc);
  assert(target);
  int64_t delta = (int64_t)target - (int64_t)(loc + 4);
  assert(fits_in_32(delta));
  memcpy(loc, &delta, sizeof(int32_t));
}

void asm_patch_jcc32(emit_state *s, uint8_t *loc, uint8_t *target) {
  (void)s;
  assert(loc);
  assert(target);
  int64_t delta = (int64_t)target - (int64_t)(loc + 4);
  assert(fits_in_32(delta));
  memcpy(loc, &delta, sizeof(int32_t));
}

void asm_write_jmp32_at(emit_state *s, uint8_t *loc, uint8_t *target) {
  (void)s;
  assert(loc);
  assert(target);
  int64_t delta = (int64_t)target - ((int64_t)loc + 5);
  assert(fits_in_32(delta));
  loc[0] = 0xe9;
  memcpy(loc + 1, &delta, sizeof(int32_t));
}

static void emit_cmp_reg_imm32(emit_state *s, uint8_t r, int32_t imm) {
  if ((int32_t)((int8_t)imm) == imm) {
    emit_reg_reg(s, 0x83, 7, r);
    emit_byte(s, (uint8_t)imm);
  } else {
    emit_reg_reg(s, 0x81, 7, r);
    emit_imm32(s, (uint32_t)imm);
  }
}

void emit_jcc32(emit_state *s, enum jcc_cond cond, label *target) {
  assert(target);
  if (target->emitted) {
    int64_t cur = emit_offset(s);
    int64_t short_delta = (int64_t)target->addr - (cur + 2);
    if ((int32_t)((int8_t)short_delta) == short_delta) {
      emit_byte(s, (uint8_t)(cond - 0x10));
      emit_byte(s, (uint8_t)short_delta);
      return;
    }

    int64_t delta = (int64_t)target->addr - (cur + 6);
    assert(fits_in_32(delta));
    emit_byte(s, 0x0f);
    emit_byte(s, cond);
    emit_imm32(s, (uint32_t)delta);
    return;
  }

  // Unresolved label: always use the long encoding for easier patching.
  emit_byte(s, 0x0f);
  emit_byte(s, cond);
  auto loc = emit_imm32(s, 0);
  label_add_patch(s, target, LABEL_PATCH_JCC32, loc);
}

void emit_jmp32(emit_state *s, label *target) {
  assert(target);
  if (target->emitted) {
    int64_t delta = (int64_t)target->addr - (emit_offset(s) + 5);
    assert(fits_in_32(delta));
    emit_byte(s, 0xe9);
    emit_imm32(s, (uint32_t)delta);
    return;
  }

  emit_byte(s, 0xe9);
  auto loc = emit_imm32(s, 0);
  label_add_patch(s, target, LABEL_PATCH_JMP32, loc);
}

static void emit_reg_reg(emit_state *s, uint8_t opcode, uint8_t src,
                         uint8_t dst) {
  emit_rex(s, 1, src >> 3, 0, dst >> 3);
  emit_byte(s, opcode);
  emit_modrm(s, 0x3, 0x7 & src, 0x7 & dst);
}

static void emit_sse_reg_reg(emit_state *s, uint8_t prefix, uint8_t opcode,
                             uint8_t src, uint8_t dst) {
  if (prefix) {
    emit_byte(s, prefix);
  }
  emit_rex_optional(s, 0, src >> 3, 0, dst >> 3);
  emit_byte(s, 0x0f);
  emit_byte(s, opcode);
  emit_modrm(s, 0x3, 0x7 & src, 0x7 & dst);
}

static uint8_t *emit_sse_literal_instr(emit_state *s, uint8_t prefix,
                                       uint8_t opcode, uint8_t dst) {
  if (prefix) {
    emit_byte(s, prefix);
  }
  emit_rex_optional(s, 0, dst >> 3, 0, 0);
  emit_byte(s, 0x0f);
  emit_byte(s, opcode);
  emit_modrm(s, 0x0, 0x7 & dst, 0x5);
  return emit_imm32(s, 0);
}

static void emit_sse_literal_constant(emit_state *s, uint8_t prefix,
                                      uint8_t opcode, uint8_t dst, int idx) {
  assert(idx >= 0);
  assert((size_t)idx < arrlen(s->const_pool));
  constant_entry *entry = &s->const_pool[idx];
  uint8_t *disp = emit_sse_literal_instr(s, prefix, opcode, dst);
  const_patch patch = {.inst0 = disp, .inst1 = nullptr};
  arrput(nullptr, entry->patches, patch);
}

static void emit_mem_reg_sib(emit_state *s, uint8_t opcode, int32_t offset,
                             uint8_t scale, uint8_t index, uint8_t base,
                             uint8_t reg) {
  bool disp8 = (int32_t)((int8_t)offset) == offset;
  uint8_t mod;
  if (offset == 0 && base != RBP) {
    mod = 0x0;
  } else if (disp8) {
    mod = 0x1;
  } else {
    mod = 0x2;
  }

  emit_rex(s, 1, reg >> 3, index >> 3, base >> 3);
  emit_byte(s, opcode);
  emit_modrm(s, mod, 0x7 & reg, 0x4);
  emit_sib(s, scale, index, base);
  if (mod == 0x1) {
    emit_byte(s, (uint8_t)offset);
  } else if (mod == 0x2 || (mod == 0x0 && base == RBP)) {
    emit_imm32(s, (uint32_t)offset);
  }
}

static void emit_mem_reg(emit_state *s, uint8_t opcode, int32_t offset,
                         uint8_t r1, uint8_t r2) {
  if (low3bits(r1) == RSP) {
    emit_mem_reg_sib(s, opcode, offset, 0, RSP, r1, r2);
  } else {
    bool disp8 = (int32_t)((int8_t)offset) == offset;
    uint8_t mod;
    if (offset == 0 && low3bits(r1) != RBP) {
      mod = 0x0;
    } else if (disp8) {
      mod = 0x1;
    } else {
      mod = 0x2;
    }

    emit_rex(s, 1, r2 >> 3, 0, r1 >> 3);
    emit_byte(s, opcode);
    emit_modrm(s, mod, 0x7 & r2, 0x7 & r1);
    if (mod == 0x1) {
      emit_byte(s, (uint8_t)offset);
    } else if (mod == 0x2) {
      emit_imm32(s, (uint32_t)offset);
    }
  }
}

static void emit_sse_mem(emit_state *s, uint8_t prefix, uint8_t opcode,
                         int32_t offset, uint8_t base, uint8_t freg) {
  bool disp8 = (int32_t)((int8_t)offset) == offset;
  uint8_t mod;
  if (offset == 0 && low3bits(base) != RBP) {
    mod = 0x0;
  } else if (disp8) {
    mod = 0x1;
  } else {
    mod = 0x2;
  }

  if (prefix) {
    emit_byte(s, prefix);
  }
  emit_rex_optional(s, 0, freg >> 3, 0, base >> 3);
  emit_byte(s, 0x0f);
  emit_byte(s, opcode);

  if (low3bits(base) == RSP) {
    emit_modrm(s, mod, 0x7 & freg, 0x4);
    emit_sib(s, 0, RSP, base);
  } else {
    emit_modrm(s, mod, 0x7 & freg, 0x7 & base);
  }

  if (mod == 0x1) {
    emit_byte(s, (uint8_t)offset);
  } else if (mod == 0x2) {
    emit_imm32(s, (uint32_t)offset);
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

/////////////////// opcodes

static void emit_arith_imm(emit_state *s, enum ARITH_CODES op, uint8_t src,
                           int32_t imm) {
  if ((int32_t)((int8_t)imm) == imm) {
    emit_reg_reg(s, 0x83, op, src);
    emit_byte(s, (uint8_t)imm);
  } else {
    emit_reg_reg(s, 0x81, op, src);
    emit_imm32(s, (uint32_t)imm);
  }
}

static void emit_neg(emit_state *s, uint8_t r) {
  emit_rex_optional(s, 0, 0, 0, r >> 3);
  emit_byte(s, 0xf7);
  emit_modrm(s, 0x3, 0x3, 0x7 & r);
}
static void emit_fneg(emit_state *s, uint8_t r) {
  assert(r >= FPR_REG_START && r < X64_MAX_REG);
  uint8_t hw = hw_fpr(r);
  int idx = add_constant(s, -0.0);
  constant_entry *entry = &s->const_pool[idx];

  emit_byte(s, 0x66);
  emit_rex_optional(s, 0, hw >> 3, 0, 0);
  emit_byte(s, 0x0f);
  emit_byte(s, 0x57);
  emit_modrm(s, 0x0, 0x7 & hw, 0x5);
  uint8_t *disp = emit_imm32(s, 0);

  const_patch patch = {.inst0 = disp, .inst1 = nullptr};
  arrput(&s->z, entry->patches, patch);
}

void emit_push(emit_state *s, uint8_t r) {
  emit_rex_optional(s, 0, 0, 0, r >> 3);
  emit_byte(s, (uint8_t)(0x50 + (0x7 & r)));
}

void emit_pop(emit_state *s, uint8_t r) {
  emit_rex_optional(s, 0, 0, 0, r >> 3);
  emit_byte(s, (uint8_t)(0x58 | (0x7 & r)));
}

void emit_debugtrap(emit_state *s) { emit_byte(s, 0xcc); }

void emit_push_regs(emit_state *s, uint8_t const *regs, size_t count,
                    bool abi) {
  bool odd = (count + abi) & 1;
  if (odd) {
    emit_sub_constant(s, RSP, RSP, 8);
  }
  for (size_t i = 0; i < count; i++) {
    uint8_t reg = regs[i];
    if (reg >= FPR_REG_START) {
      emit_sub_constant(s, RSP, RSP, 16);
      emit_fstore(s, 0, RSP, reg);
    } else {
      emit_push(s, reg);
    }
  }
}

void emit_pop_regs(emit_state *s, uint8_t const *regs, size_t count, bool abi) {
  bool odd = (count + abi) & 1;
  for (size_t i = count; i > 0; i--) {
    uint8_t reg = regs[i - 1];
    if (reg >= FPR_REG_START) {
      emit_fmem_load(s, 0, RSP, reg);
      emit_add_constant(s, RSP, RSP, 16);
    } else {
      emit_pop(s, reg);
    }
  }
  if (odd) {
    emit_add_constant(s, RSP, RSP, 8);
  }
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
    emit_mov64(s, RTMP, imm);
    emit_cmp(s, reg, RTMP);
  }
}

void emit_test_constant(emit_state *s, uint8_t reg, int64_t imm) {
  assert(reg < FPR_REG_START);
  if (!fits_in_32(imm)) {
    abort();
  }
  emit_reg_reg(s, ASM_TEST_IMM, 0, reg);
  emit_imm32(s, (uint32_t)imm);
}

void emit_and_constant(emit_state *s, uint8_t dst, uint8_t src, int64_t imm) {
  assert(dst < FPR_REG_START);
  assert(src < FPR_REG_START);
  if (!fits_in_32(imm)) {
    abort();
  }
  int32_t imm32 = (int32_t)imm;
  if ((int32_t)((int8_t)imm32) == imm32) {
    emit_reg_reg(s, ASM_AND, 4, dst);
    emit_byte(s, (uint8_t)imm32);
  } else {
    emit_reg_reg(s, ASM_AND_IMM, 4, dst);
    emit_imm32(s, (uint32_t)imm32);
  }
  if (dst != src) {
    emit_mov(s, dst, src);
  }
}

void emit_add(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  if (dst == lhs) {
    emit_reg_reg(s, ASM_ADD, lhs, rhs);
  } else if (rhs == dst) {
    emit_reg_reg(s, ASM_ADD, dst, lhs);
  } else {
    emit_mov(s, dst, lhs);
    emit_reg_reg(s, ASM_ADD, dst, rhs);
  }
}
static void emit_add_sub_constant(emit_state *s, enum ARITH_CODES op,
                                  uint8_t dst, uint8_t lhs, int64_t imm) {
  if (fits_in_32(imm)) {
    if (dst != lhs) {
      emit_mov(s, dst, lhs);
    }
    emit_arith_imm(s, op, dst, (int32_t)imm);
    return;
  }

  emit_mov64(s, RTMP, imm);
  if (op == ASM_ARITH_ADD) {
    emit_add(s, dst, lhs, RTMP);
  } else {
    emit_sub(s, dst, lhs, RTMP);
  }
}

// Slightly different from emit_add, since we need to negate if reversed.
void emit_sub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  if (dst == lhs && dst != rhs) {
    emit_reg_reg(s, ASM_SUB, dst, rhs);
    return;
  }

  if (rhs == dst) {
    emit_mov(s, RTMP, rhs);
    emit_mov(s, dst, lhs);
    emit_reg_reg(s, ASM_SUB, dst, RTMP);
    return;
  }

  if (dst != lhs) {
    emit_mov(s, dst, lhs);
  }
  emit_reg_reg(s, ASM_SUB, dst, rhs);
}
void emit_fadd(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  if (dst == lhs) {
    emit_sse_reg_reg(s, 0xF2, 0x58, hw_fpr(lhs), hw_fpr(rhs));
  } else if (rhs == dst) {
    emit_sse_reg_reg(s, 0xF2, 0x58, hw_fpr(dst), hw_fpr(lhs));
  } else {
    emit_fmov(s, dst, lhs);
    emit_sse_reg_reg(s, 0xF2, 0x58, hw_fpr(dst), hw_fpr(rhs));
  }
}

void emit_fsub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  if (dst == lhs) {
    emit_sse_reg_reg(s, 0xF2, 0x5C, hw_fpr(lhs), hw_fpr(rhs));
  } else if (rhs == dst) {
    emit_sse_reg_reg(s, 0xF2, 0x5C, hw_fpr(dst), hw_fpr(lhs));
    emit_fneg(s, dst);
  } else {
    emit_fmov(s, dst, lhs);
    emit_sse_reg_reg(s, 0xF2, 0x5C, hw_fpr(dst), hw_fpr(rhs));
  }
}

void emit_fadd_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  int idx = add_constant(s, imm);
  if (dst != lhs) {
    emit_fmov(s, dst, lhs);
  }
  emit_sse_literal_constant(s, 0xF2, 0x58, hw_fpr(dst), idx);
}

void emit_fsub_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  int idx = add_constant(s, imm);
  if (dst != lhs) {
    emit_fmov(s, dst, lhs);
  }
  emit_sse_literal_constant(s, 0xF2, 0x5C, hw_fpr(dst), idx);
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
  emit_mov64(s, RTMP, value);
  emit_store(s, offset, base, RTMP);
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
