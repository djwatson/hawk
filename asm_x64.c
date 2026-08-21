// Copyright 2023 Dave Watson

#define _DEFAULT_SOURCE

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "asm.h"
#include "hawk.h"
#include "types.h"

static inline uint8_t hw_fpr(uint8_t reg) {
  assert(reg >= FPR_REG_START && reg < X64_MAX_REG);
  return reg - FPR_REG_START;
}

static uint8_t low3bits(uint8_t r) { return 0x7 & r; }
static bool fits_in_8(int64_t value) { return value == (int64_t)(int8_t)value; }
static bool fits_in_32(int64_t value) {
  return value == (int64_t)(int32_t)value;
}
static bool fits_in_u32(int64_t value) {
  return value >= 0 && value <= (int64_t)UINT32_MAX;
}

static uint8_t pick_tmp(uint8_t reg0, uint8_t reg1) {
  if (RTMP != reg0 && RTMP != reg1) return RTMP;
  if (RTMP2 != reg0 && RTMP2 != reg1) return RTMP2;
  abort();
}

/////////////////// instruction encoding

typedef uint64_t x64_op;

#define OP1(a) ((x64_op)(a) | (UINT64_C(1) << 32))
#define OP2(a, b) ((x64_op)(a) | ((x64_op)(b) << 8) | (UINT64_C(2) << 32))
#define OP3(a, b, c)                                                           \
  ((x64_op)(a) | ((x64_op)(b) << 8) | ((x64_op)(c) << 16) | (UINT64_C(3) << 32))
#define OP4(a, b, c, d)                                                        \
  ((x64_op)(a) | ((x64_op)(b) << 8) | ((x64_op)(c) << 16) |                    \
   ((x64_op)(d) << 24) | (UINT64_C(4) << 32))
#define OP_W(op) ((op) | (UINT64_C(1) << 35))

enum : uint64_t {
  XO_ADD = OP_W(OP1(0x03)),
  XO_SUB = OP_W(OP1(0x2b)),
  XO_MOV = OP_W(OP1(0x8b)),
  XO_MOVTO = OP_W(OP1(0x89)),
  XO_MOVBTO = OP1(0x88),
  XO_MOVZXB = OP_W(OP2(0x0f, 0xb6)),
  XO_ARITHI = OP_W(OP1(0x81)),
  XO_ARITHI8 = OP_W(OP1(0x83)),
  XO_ARITHBI = OP1(0x80),
  XO_CMP = OP_W(OP1(0x3b)),
  XO_CMPTO = OP_W(OP1(0x39)),
  XO_GROUP3 = OP_W(OP1(0xf7)),
  XO_SHIFTI = OP_W(OP1(0xc1)),
  XO_IMUL = OP_W(OP2(0x0f, 0xaf)),
  XO_IMULI = OP_W(OP1(0x69)),
  XO_IMULI8 = OP_W(OP1(0x6b)),
  XO_MOVMI = OP_W(OP1(0xc7)),
  XO_MOVBMI = OP1(0xc6),
  XO_MOVAPD = OP3(0x66, 0x0f, 0x28),
  XO_UCOMISD = OP3(0x66, 0x0f, 0x2e),
  XO_MOVSD = OP3(0xf2, 0x0f, 0x10),
  XO_MOVSDTO = OP3(0xf2, 0x0f, 0x11),
  XO_SQRTSD = OP3(0xf2, 0x0f, 0x51),
  XO_ADDSD = OP3(0xf2, 0x0f, 0x58),
  XO_SUBSD = OP3(0xf2, 0x0f, 0x5c),
  XO_MULSD = OP3(0xf2, 0x0f, 0x59),
  XO_DIVSD = OP3(0xf2, 0x0f, 0x5e),
  XO_CVTSI2SD = OP_W(OP3(0xf2, 0x0f, 0x2a)),
  XO_CVTTSD2SI = OP_W(OP3(0xf2, 0x0f, 0x2c)),
  XO_ROUNDSD = OP4(0x66, 0x0f, 0x3a, 0x0b),
};

static void emit_rex(emit_state *s, uint8_t w, uint8_t r, uint8_t x,
                     uint8_t b) {
  emit_byte(s, 0x40 | (w << 3) | (r << 2) | (x << 1) | b);
}

static void emit_rex_optional_force(emit_state *s, uint8_t w, uint8_t r,
                                    uint8_t x, uint8_t b, bool force) {
  if (w | r | x | b | force) {
    emit_rex(s, w, r, x, b);
  }
}

static void emit_rex_optional(emit_state *s, uint8_t w, uint8_t r, uint8_t x,
                              uint8_t b) {
  emit_rex_optional_force(s, w, r, x, b, false);
}

static void emit_modrm(emit_state *s, uint8_t mod, uint8_t reg, uint8_t rm) {
  emit_byte(s, (mod << 6) | (reg << 3) | rm);
}

static void emit_sib(emit_state *s, uint8_t scale, uint8_t index,
                     uint8_t base) {
  emit_byte(s, (scale << 6) | ((0x7 & index) << 3) | (0x7 & base));
}

static void emit_opcode(emit_state *s, x64_op op, uint8_t reg, uint8_t index,
                        uint8_t base, bool force_rex) {
  uint8_t len = (uint8_t)((op >> 32) & 0x7);
  uint32_t bytes = (uint32_t)op;
  uint8_t first = (uint8_t)bytes;
  // Legacy prefixes precede REX; opcode escapes follow it.
  if (first == 0x66 || first == 0xf2 || first == 0xf3) {
    emit_byte(s, first);
    bytes >>= 8;
    len--;
  }
  emit_rex_optional_force(s, (op >> 35) & 1, reg >> 3, index >> 3, base >> 3,
                          force_rex);
  while (len--) {
    emit_byte(s, (uint8_t)bytes);
    bytes >>= 8;
  }
}

static void emit_rr(emit_state *s, x64_op op, uint8_t reg, uint8_t rm) {
  emit_opcode(s, op, reg, 0, rm, false);
  emit_modrm(s, 0x3, low3bits(reg), low3bits(rm));
}

static void emit_displacement(emit_state *s, uint8_t mod, int32_t offset) {
  if (mod == 1) {
    emit_byte(s, (uint8_t)offset);
  } else if (mod == 2) {
    emit_imm32(s, (uint32_t)offset);
  }
}

static uint8_t memory_mode(uint8_t base, int32_t offset) {
  if (offset == 0 && low3bits(base) != RBP) {
    return 0;
  }
  return fits_in_8(offset) ? 1 : 2;
}

static void emit_rmro_force(emit_state *s, x64_op op, uint8_t reg, uint8_t base,
                            int32_t offset, bool force_rex) {
  uint8_t mod = memory_mode(base, offset);
  emit_opcode(s, op, reg, 0, base, force_rex);
  emit_modrm(s, mod, low3bits(reg),
             low3bits(base) == RSP ? RSP : low3bits(base));
  if (low3bits(base) == RSP) {
    emit_sib(s, 0, RSP, base);
  }
  emit_displacement(s, mod, offset);
}

static void emit_rmro(emit_state *s, x64_op op, uint8_t reg, uint8_t base,
                      int32_t offset) {
  emit_rmro_force(s, op, reg, base, offset, false);
}

static void emit_rmroi_force(emit_state *s, x64_op op, uint8_t reg,
                             uint8_t base, uint8_t index, int32_t offset,
                             bool force_rex) {
  assert(low3bits(index) != RSP);
  uint8_t mod = memory_mode(base, offset);
  emit_opcode(s, op, reg, index, base, force_rex);
  emit_modrm(s, mod, low3bits(reg), RSP);
  emit_sib(s, 0, index, base);
  emit_displacement(s, mod, offset);
}

static void emit_rmroi(emit_state *s, x64_op op, uint8_t reg, uint8_t base,
                       uint8_t index, int32_t offset) {
  emit_rmroi_force(s, op, reg, base, index, offset, false);
}

static uint8_t *emit_riprel(emit_state *s, x64_op op, uint8_t reg) {
  emit_opcode(s, op, reg, 0, 0, false);
  emit_modrm(s, 0, low3bits(reg), RBP);
  return emit_imm32(s, 0);
}

uint8_t *asm_emit_mov64_patchable(emit_state *s, uint8_t r, int64_t imm) {
  assert(r < FPR_REG_START);
  uint8_t *loc = (uint8_t *)emit_offset(s);
  emit_rex(s, 1, 0, 0, r >> 3);
  emit_byte(s, 0xb8 | (0x7 & r));
  emit_imm64(s, (uint64_t)imm);
  return loc;
}

bool asm_mov64_patchable_is_live(uint8_t const *loc) {
  assert(loc);
  return (loc[0] & 0xfe) == 0x48 && (loc[1] & 0xf8) == 0xb8;
}

int64_t asm_read_mov64_patchable(uint8_t const *loc) {
  assert(loc);
  assert(asm_mov64_patchable_is_live(loc));
  int64_t imm = 0;
  memcpy(&imm, loc + 2, sizeof(imm));
  return imm;
}

void asm_patch_mov64_patchable(emit_state *s, uint8_t *loc, int64_t imm) {
  (void)s;
  assert(loc);
  assert(asm_mov64_patchable_is_live(loc));
  memcpy(loc + 2, &imm, sizeof(imm));
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

void emit_call_reg(emit_state *s, uint8_t r) {
  emit_rex_optional(s, 0, 0, 0, r >> 3);
  emit_byte(s, 0xff);
  emit_modrm(s, 0x3, 0x2, 0x7 & r);
}

static int32_t relative_32(int64_t target, int64_t end) {
  int64_t delta = target - end;
  assert(fits_in_32(delta));
  return (int32_t)delta;
}

void emit_call32(emit_state *s, int64_t target) {
  int32_t delta = relative_32(target, emit_offset(s) + 5);
  emit_byte(s, 0xe8);
  emit_imm32(s, (uint32_t)delta);
}

void emit_ret(emit_state *s) { emit_byte(s, 0xc3); }

static void patch_relative_32(uint8_t *loc, uint8_t const *target) {
  assert(loc);
  assert(target);
  int32_t delta = relative_32((int64_t)target, (int64_t)(loc + 4));
  memcpy(loc, &delta, sizeof(delta));
}

void asm_patch_jmp32(emit_state *s, uint8_t *loc, uint8_t const *target) {
  (void)s;
  patch_relative_32(loc, target);
}

void asm_patch_jcc32(emit_state *s, uint8_t *loc, uint8_t const *target) {
  (void)s;
  patch_relative_32(loc, target);
}

bool asm_jcc32_can_reach(uint8_t const *loc, uint8_t const *target) {
  int64_t delta = (int64_t)target - (int64_t)(loc + 4);
  return fits_in_32(delta);
}

uint8_t *asm_jcc32_start(uint8_t *loc) { return loc - 2; }

uint8_t *asm_jcc32_end(uint8_t *loc) { return loc + 4; }

void asm_write_jmp32_at(emit_state *s, uint8_t *loc, uint8_t const *target) {
  (void)s;
  assert(loc);
  assert(target);
  int32_t delta = relative_32((int64_t)target, (int64_t)loc + 5);
  loc[0] = 0xe9;
  memcpy(loc + 1, &delta, sizeof(delta));
}

void asm_emit_jmp32_resolved(emit_state *s, uint8_t const *target) {
  int32_t delta = relative_32((int64_t)target, emit_offset(s) + 5);
  emit_byte(s, 0xe9);
  emit_imm32(s, (uint32_t)delta);
}

uint8_t *asm_emit_jmp32_placeholder(emit_state *s) {
  emit_byte(s, 0xe9);
  return emit_imm32(s, 0);
}

void asm_emit_jcc32_resolved(emit_state *s, enum jcc_cond cond,
                             uint8_t const *target) {
  int64_t cur = emit_offset(s);
  int64_t short_delta = (int64_t)target - (cur + 2);
  if ((int32_t)((int8_t)short_delta) == short_delta) {
    emit_byte(s, (uint8_t)(cond - 0x10));
    emit_byte(s, (uint8_t)short_delta);
    return;
  }

  int32_t delta = relative_32((int64_t)target, cur + 6);
  emit_byte(s, 0x0f);
  emit_byte(s, cond);
  emit_imm32(s, (uint32_t)delta);
}

uint8_t *asm_emit_jcc32_placeholder(emit_state *s, enum jcc_cond cond) {
  emit_byte(s, 0x0f);
  emit_byte(s, cond);
  return emit_imm32(s, 0);
}

static void emit_literal_constant(emit_state *s, x64_op op, uint8_t dst,
                                  int idx) {
  assert(idx >= 0);
  assert((size_t)idx < arrlen(s->const_pool));
  constant_entry *entry = &s->const_pool[idx];
  uint8_t *disp = emit_riprel(s, op, dst);
  const_patch patch = {.inst0 = disp, .inst1 = nullptr};
  arrput(entry->patches, patch);
}

void emit_mem_load(emit_state *s, int32_t offset, uint8_t base, uint8_t dst) {
  assert(dst < MAX_REG);
  emit_rmro(s, XO_MOV, dst, base, offset);
}

void emit_mem_load_indexed(emit_state *s, int32_t offset, uint8_t base,
                           uint8_t index, uint8_t dst) {
  assert(base < FPR_REG_START && index < FPR_REG_START);
  assert(dst < FPR_REG_START);
  emit_rmroi(s, XO_MOV, dst, base, index, offset);
}

void emit_mem_load_u8(emit_state *s, int32_t offset, uint8_t base,
                      uint8_t dst) {
  assert(base < FPR_REG_START);
  assert(dst < FPR_REG_START);
  emit_rmro(s, XO_MOVZXB, dst, base, offset);
}

void emit_mem_load_u8_indexed(emit_state *s, int32_t offset, uint8_t base,
                              uint8_t index, uint8_t dst) {
  assert(base < FPR_REG_START && index < FPR_REG_START);
  assert(dst < FPR_REG_START);
  emit_rmroi(s, XO_MOVZXB, dst, base, index, offset);
}

void emit_mem_cmp_constant(emit_state *s, int32_t offset, uint8_t base,
                           int64_t value) {
  assert(base < FPR_REG_START);
  if (fits_in_32(value)) {
    int32_t imm = (int32_t)value;
    emit_rmro(s, fits_in_8(imm) ? XO_ARITHI8 : XO_ARITHI, 7, base, offset);
    if (fits_in_8(imm))
      emit_byte(s, (uint8_t)imm);
    else
      emit_imm32(s, (uint32_t)imm);
    return;
  }
  uint8_t tmp = pick_tmp(base, REG_NONE);
  emit_mov64(s, tmp, value);
  emit_rmro(s, XO_CMPTO, tmp, base, offset);
}

void emit_mem_cmp_u8_constant(emit_state *s, int32_t offset, uint8_t base,
                              uint8_t value) {
  assert(base < FPR_REG_START);
  emit_rmro(s, XO_ARITHBI, 7, base, offset);
  emit_byte(s, value);
}

void emit_fmem_load(emit_state *s, int32_t offset, uint8_t base, uint8_t dst) {
  assert(dst >= FPR_REG_START && dst < X64_MAX_REG);
  assert(base < FPR_REG_START);
  emit_rmro(s, XO_MOVSD, hw_fpr(dst), base, offset);
}

void emit_fmem_load_indexed(emit_state *s, int32_t offset, uint8_t base,
                            uint8_t index, uint8_t dst) {
  assert(dst >= FPR_REG_START && dst < X64_MAX_REG);
  assert(base < FPR_REG_START && index < FPR_REG_START);
  emit_rmroi(s, XO_MOVSD, hw_fpr(dst), base, index, offset);
}

/////////////////// opcodes

static void emit_group_imm(emit_state *s, uint8_t group, uint8_t reg,
                           int32_t imm) {
  if (fits_in_8(imm)) {
    emit_rr(s, XO_ARITHI8, group, reg);
    emit_byte(s, (uint8_t)imm);
  } else {
    emit_rr(s, XO_ARITHI, group, reg);
    emit_imm32(s, (uint32_t)imm);
  }
}

static void emit_cqo(emit_state *s) {
  emit_rex(s, 1, 0, 0, 0);
  emit_byte(s, 0x99);
}

static void emit_idiv_signed(emit_state *s, uint8_t divisor) {
  emit_rr(s, XO_GROUP3, 7, divisor);
}

static void emit_stack_reg(emit_state *s, uint8_t op, uint8_t r) {
  emit_rex_optional(s, 0, 0, 0, r >> 3);
  emit_byte(s, op | low3bits(r));
}

void emit_push(emit_state *s, uint8_t r) { emit_stack_reg(s, 0x50, r); }
void emit_pop(emit_state *s, uint8_t r) { emit_stack_reg(s, 0x58, r); }

void emit_debugtrap(emit_state *s) { emit_byte(s, 0xcc); }

static size_t register_frame_slots(size_t count, bool abi) {
  return count + (((count + (size_t)abi) & 1) ? 0 : 1);
}

static void emit_register_slot(emit_state *s, uint8_t reg, int32_t offset,
                               bool restore) {
  if (restore) {
    reg >= FPR_REG_START ? emit_fmem_load(s, offset, RSP, reg)
                         : emit_mem_load(s, offset, RSP, reg);
  } else {
    reg >= FPR_REG_START ? emit_fstore(s, offset, RSP, reg)
                         : emit_store(s, offset, RSP, reg);
  }
}

void emit_push_regs(emit_state *s, uint8_t const *regs, size_t count,
                    bool abi) {
  size_t frame_slots = register_frame_slots(count, abi);
  if (frame_slots == 0) {
    return;
  }
  emit_sub_constant(s, RSP, RSP, (int64_t)(frame_slots * 8));
  for (size_t i = 0; i < count; i++) {
    uint8_t reg = regs[i];
    if (reg == REG_NONE) {
      continue;
    }
    emit_register_slot(s, reg, (int32_t)(i * 8), false);
  }
}

void emit_pop_regs(emit_state *s, uint8_t const *regs, size_t count, bool abi) {
  for (size_t i = count; i > 0; i--) {
    uint8_t reg = regs[i - 1];
    if (reg == REG_NONE) {
      continue;
    }
    emit_register_slot(s, reg, (int32_t)((i - 1) * 8), true);
  }
  size_t frame_slots = register_frame_slots(count, abi);
  if (frame_slots != 0) {
    emit_add_constant(s, RSP, RSP, (int64_t)(frame_slots * 8));
  }
}

void emit_mov(emit_state *s, uint8_t dst, uint8_t src) {
  if (dst == src) {
    return;
  }
  emit_rr(s, XO_MOV, dst, src);
}
void emit_cmp(emit_state *s, uint8_t lhs, uint8_t rhs) {
  assert(lhs < FPR_REG_START);
  assert(rhs < FPR_REG_START);
  emit_rr(s, XO_CMP, lhs, rhs);
}
void emit_fcmp(emit_state *s, uint8_t lhs, uint8_t rhs) {
  emit_rr(s, XO_UCOMISD, hw_fpr(lhs), hw_fpr(rhs));
}
void emit_fcmp_constant(emit_state *s, uint8_t reg, double imm) {
  int idx = add_constant(s, imm);
  emit_literal_constant(s, XO_UCOMISD, hw_fpr(reg), idx);
}

void emit_fmov_constant(emit_state *s, uint8_t dst, double imm) {
  int idx = add_constant(s, imm);
  load_constant(s, idx, dst);
}
void emit_fmov(emit_state *s, uint8_t dst, uint8_t src) {
  if (dst == src) {
    return;
  }
  emit_rr(s, XO_MOVAPD, hw_fpr(dst), hw_fpr(src));
}
void emit_fsqrt(emit_state *s, uint8_t dst, uint8_t src) {
  assert(dst >= FPR_REG_START && dst < X64_MAX_REG);
  assert(src >= FPR_REG_START && src < X64_MAX_REG);
  emit_rr(s, XO_SQRTSD, hw_fpr(dst), hw_fpr(src));
}
void emit_int64_to_double(emit_state *s, uint8_t dst, uint8_t src) {
  assert(dst >= FPR_REG_START && dst < X64_MAX_REG);
  assert(src < FPR_REG_START);
  emit_rr(s, XO_CVTSI2SD, hw_fpr(dst), src);
}
void emit_double_to_int64_trunc(emit_state *s, uint8_t dst, uint8_t src) {
  assert(dst < FPR_REG_START);
  assert(src >= FPR_REG_START && src < X64_MAX_REG);
  emit_rr(s, XO_CVTTSD2SI, dst, hw_fpr(src));
}
void emit_ftruncate(emit_state *s, uint8_t dst, uint8_t src) {
  assert(dst >= FPR_REG_START && dst < X64_MAX_REG);
  assert(src >= FPR_REG_START && src < X64_MAX_REG);
  emit_rr(s, XO_ROUNDSD, hw_fpr(dst), hw_fpr(src));
  emit_byte(s, 0x03); // round toward zero
}

static void emit_move_any(emit_state *s, uint8_t dst, uint8_t src) {
  if (dst >= FPR_REG_START) {
    emit_fmov(s, dst, src);
  } else {
    emit_mov(s, dst, src);
  }
}

static void emit_binop(emit_state *s, x64_op op, uint8_t dst, uint8_t lhs,
                       uint8_t rhs, bool commutative) {
  bool fp = dst >= FPR_REG_START;
  assert((lhs >= FPR_REG_START) == fp && (rhs >= FPR_REG_START) == fp);
  if (dst == rhs && !commutative) {
    uint8_t tmp = fp ? FRTMP : RTMP;
    emit_move_any(s, tmp, lhs);
    emit_rr(s, op, fp ? hw_fpr(tmp) : tmp, fp ? hw_fpr(rhs) : rhs);
    emit_move_any(s, dst, tmp);
    return;
  }
  if (dst == rhs) {
    emit_rr(s, op, fp ? hw_fpr(dst) : dst, fp ? hw_fpr(lhs) : lhs);
    return;
  }
  emit_move_any(s, dst, lhs);
  emit_rr(s, op, fp ? hw_fpr(dst) : dst, fp ? hw_fpr(rhs) : rhs);
}
void emit_cmp_constant(emit_state *s, uint8_t reg, int64_t imm) {
  assert(reg < FPR_REG_START);
  if (fits_in_32(imm)) {
    emit_group_imm(s, 7, reg, (int32_t)imm);
  } else {
    uint8_t tmp = pick_tmp(reg, REG_NONE);
    emit_mov64(s, tmp, imm);
    emit_cmp(s, reg, tmp);
  }
}

void emit_test_constant(emit_state *s, uint8_t reg, int64_t imm) {
  assert(reg < FPR_REG_START);
  if (!fits_in_32(imm)) {
    abort();
  }
  emit_rr(s, XO_GROUP3, 0, reg);
  emit_imm32(s, (uint32_t)imm);
}

void emit_and_constant(emit_state *s, uint8_t dst, uint8_t src, int64_t imm) {
  assert(dst < FPR_REG_START);
  assert(src < FPR_REG_START);
  if (!fits_in_32(imm)) {
    abort();
  }
  if (dst != src) {
    emit_mov(s, dst, src);
  }
  emit_group_imm(s, 4, dst, (int32_t)imm);
}

void emit_add(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_binop(s, XO_ADD, dst, lhs, rhs, true);
}

static void emit_add_sub_constant(emit_state *s, x64_op op, uint8_t group,
                                  uint8_t dst, uint8_t lhs, int64_t imm) {
  if (fits_in_32(imm)) {
    emit_mov(s, dst, lhs);
    emit_group_imm(s, group, dst, (int32_t)imm);
    return;
  }

  uint8_t tmp = pick_tmp(dst, lhs);
  emit_mov64(s, tmp, imm);
  emit_binop(s, op, dst, lhs, tmp, group == 0);
}

void emit_sub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_binop(s, XO_SUB, dst, lhs, rhs, false);
}

void emit_mul(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_binop(s, XO_IMUL, dst, lhs, rhs, true);
}

static void emit_mul_imm32(emit_state *s, uint8_t dst, uint8_t lhs,
                           int32_t imm) {
  if (fits_in_8(imm)) {
    emit_rr(s, XO_IMULI8, dst, lhs);
    emit_byte(s, (uint8_t)imm);
  } else {
    emit_rr(s, XO_IMULI, dst, lhs);
    emit_imm32(s, (uint32_t)imm);
  }
}

void emit_mul_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm) {
  assert(dst < FPR_REG_START);
  assert(lhs < FPR_REG_START);
  if (fits_in_32(imm)) {
    emit_mul_imm32(s, dst, lhs, (int32_t)imm);
    return;
  }
  uint8_t tmp = pick_tmp(dst, lhs);
  emit_mov64(s, tmp, imm);
  emit_mul(s, dst, lhs, tmp);
}

#define DEFINE_FIXNUM_GUARD_OVERFLOW(name)                                     \
  void asm_emit_fixnum_##name##_guard_overflow(emit_state *s, uint8_t dst,     \
                                               uint8_t lhs, uint8_t rhs,       \
                                               label *overflow_target) {       \
    emit_##name(s, dst, lhs, rhs);                                             \
    emit_jcc32(s, JO, overflow_target);                                        \
  }                                                                            \
  void asm_emit_fixnum_##name##_constant_guard_overflow(                       \
      emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm,                    \
      label *overflow_target) {                                                \
    emit_##name##_constant(s, dst, lhs, imm);                                  \
    emit_jcc32(s, JO, overflow_target);                                        \
  }

DEFINE_FIXNUM_GUARD_OVERFLOW(add)
DEFINE_FIXNUM_GUARD_OVERFLOW(sub)
DEFINE_FIXNUM_GUARD_OVERFLOW(mul)

#undef DEFINE_FIXNUM_GUARD_OVERFLOW

void emit_sar_constant(emit_state *s, uint8_t dst, uint8_t src, uint8_t imm) {
  assert(dst < FPR_REG_START);
  assert(src < FPR_REG_START);
  emit_mov(s, dst, src);
  emit_rr(s, XO_SHIFTI, 7, dst);
  emit_byte(s, imm);
}

void emit_shl_constant(emit_state *s, uint8_t dst, uint8_t src, uint8_t imm) {
  assert(dst < FPR_REG_START);
  assert(src < FPR_REG_START);
  emit_mov(s, dst, src);
  emit_rr(s, XO_SHIFTI, 4, dst);
  emit_byte(s, imm);
}

void emit_mod(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  assert(dst < FPR_REG_START);
  assert(lhs < FPR_REG_START);
  assert(rhs < FPR_REG_START);

  bool save_rax = dst != RAX;
  bool save_rdx = dst != RDX;
  if (save_rax) {
    emit_push(s, RAX);
  }
  if (save_rdx) {
    emit_push(s, RDX);
  }

  uint8_t divisor = RTMP;
  emit_mov(s, divisor, rhs);

  emit_mov(s, RAX, lhs);
  emit_cqo(s);
  emit_idiv_signed(s, divisor);

  if (dst != RDX) {
    emit_mov(s, dst, RDX);
  }

  if (save_rdx) {
    emit_pop(s, RDX);
  }
  if (save_rax) {
    emit_pop(s, RAX);
  }
}

void emit_quotient(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  assert(dst < FPR_REG_START);
  assert(lhs < FPR_REG_START);
  assert(rhs < FPR_REG_START);

  bool save_rax = dst != RAX;
  bool save_rdx = dst != RDX;
  if (save_rax) {
    emit_push(s, RAX);
  }
  if (save_rdx) {
    emit_push(s, RDX);
  }

  // Preserve operands in dedicated scratch regs to avoid register overlap:
  //   RTMP2 = lhs, RTMP = rhs
  if (rhs == RTMP2) {
    emit_mov(s, RTMP, rhs);
    emit_mov(s, RTMP2, lhs);
  } else {
    emit_mov(s, RTMP2, lhs);
    emit_mov(s, RTMP, rhs);
  }
  emit_sar_constant(s, RTMP2, RTMP2, 3);
  emit_sar_constant(s, RTMP, RTMP, 3);

  emit_mov(s, RAX, RTMP2);
  emit_cqo(s);
  emit_idiv_signed(s, RTMP);

  if (dst != RAX) {
    emit_mov(s, dst, RAX);
  }
  emit_shl_constant(s, dst, dst, 3);

  if (save_rdx) {
    emit_pop(s, RDX);
  }
  if (save_rax) {
    emit_pop(s, RAX);
  }
}

void emit_fadd(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_binop(s, XO_ADDSD, dst, lhs, rhs, true);
}

void emit_fsub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_binop(s, XO_SUBSD, dst, lhs, rhs, false);
}

void emit_fmul(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_binop(s, XO_MULSD, dst, lhs, rhs, true);
}

void emit_fdiv(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_binop(s, XO_DIVSD, dst, lhs, rhs, false);
}

static void emit_fop_constant(emit_state *s, x64_op op, uint8_t dst,
                              uint8_t lhs, double imm) {
  int idx = add_constant(s, imm);
  emit_fmov(s, dst, lhs);
  emit_literal_constant(s, op, hw_fpr(dst), idx);
}

void emit_fadd_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  emit_fop_constant(s, XO_ADDSD, dst, lhs, imm);
}
void emit_fsub_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  emit_fop_constant(s, XO_SUBSD, dst, lhs, imm);
}
void emit_fmul_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  emit_fop_constant(s, XO_MULSD, dst, lhs, imm);
}
void emit_fdiv_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  emit_fop_constant(s, XO_DIVSD, dst, lhs, imm);
}
void emit_add_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm) {
  emit_add_sub_constant(s, XO_ADD, 0, dst, lhs, imm);
}
void emit_sub_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm) {
  emit_add_sub_constant(s, XO_SUB, 5, dst, lhs, imm);
}
void emit_store(emit_state *s, int32_t offset, uint8_t base, uint8_t src) {
  emit_rmro(s, XO_MOVTO, src, base, offset);
}

void emit_store_indexed(emit_state *s, int32_t offset, uint8_t base,
                        uint8_t index, uint8_t src) {
  assert(base < FPR_REG_START && index < FPR_REG_START);
  assert(src < FPR_REG_START);
  emit_rmroi(s, XO_MOVTO, src, base, index, offset);
}

void emit_store_u8(emit_state *s, int32_t offset, uint8_t base, uint8_t src) {
  assert(base < FPR_REG_START);
  assert(src < FPR_REG_START);
  emit_rmro_force(s, XO_MOVBTO, src, base, offset, low3bits(src) >= RSP);
}

void emit_store_u8_indexed(emit_state *s, int32_t offset, uint8_t base,
                           uint8_t index, uint8_t src) {
  assert(base < FPR_REG_START && index < FPR_REG_START);
  assert(src < FPR_REG_START);
  emit_rmroi_force(s, XO_MOVBTO, src, base, index, offset,
                   low3bits(src) >= RSP);
}

void emit_fstore(emit_state *s, int32_t offset, uint8_t base, uint8_t src) {
  assert(src >= FPR_REG_START && src < X64_MAX_REG);
  assert(base < FPR_REG_START);
  emit_rmro(s, XO_MOVSDTO, hw_fpr(src), base, offset);
}

void emit_fstore_indexed(emit_state *s, int32_t offset, uint8_t base,
                         uint8_t index, uint8_t src) {
  assert(src >= FPR_REG_START && src < X64_MAX_REG);
  assert(base < FPR_REG_START && index < FPR_REG_START);
  emit_rmroi(s, XO_MOVSDTO, hw_fpr(src), base, index, offset);
}
void emit_store_constant(emit_state *s, int32_t offset, uint8_t base,
                         int64_t value) {
  if (fits_in_32(value)) {
    // x86-64 has no imm8 encoding for MOV r/m64, imm; small immediates use
    // the sign-extending imm32 form.
    emit_rmro(s, XO_MOVMI, 0, base, offset);
    emit_imm32(s, (uint32_t)value);
    return;
  }
  uint8_t tmp = pick_tmp(base, REG_NONE);
  emit_mov64(s, tmp, value);
  emit_store(s, offset, base, tmp);
}

void emit_store_constant_indexed(emit_state *s, int32_t offset, uint8_t base,
                                 uint8_t index, int64_t value) {
  if (fits_in_32(value)) {
    emit_rmroi(s, XO_MOVMI, 0, base, index, offset);
    emit_imm32(s, (uint32_t)value);
    return;
  }
  uint8_t tmp = pick_tmp(base, index);
  emit_mov64(s, tmp, value);
  emit_store_indexed(s, offset, base, index, tmp);
}

void emit_store_u8_constant(emit_state *s, int32_t offset, uint8_t base,
                            uint8_t value) {
  emit_rmro(s, XO_MOVBMI, 0, base, offset);
  emit_byte(s, value);
}

void emit_store_u8_constant_indexed(emit_state *s, int32_t offset,
                                    uint8_t base, uint8_t index,
                                    uint8_t value) {
  emit_rmroi(s, XO_MOVBMI, 0, base, index, offset);
  emit_byte(s, value);
}

void asm_zero_alloc_payload(emit_state *s, int64_t tagged_size,
                            uint8_t size_reg) {
  assert(size_reg == REG_NONE || (size_reg != RTMP && size_reg != RTMP2));
  int64_t payload_bytes = 0;

  label loop = {};
  label done = {};

  emit_add_constant(s, RTMP, RTMP, 8);
  if (size_reg == REG_NONE) {
    payload_bytes = (tagged_size >> FIXNUM_SHIFT) - 8;
    assert(payload_bytes >= 0 && (payload_bytes % 8) == 0);
    emit_mov64(s, RTMP2, payload_bytes);
  } else {
    emit_sub_constant(s, RTMP2, size_reg, TAG_FIXNUM_VALUE(8));
    emit_sar_constant(s, RTMP2, RTMP2, FIXNUM_SHIFT);
  }
  emit_cmp_constant(s, RTMP2, 0);
  emit_jcc32(s, JE, &done);

  emit_label(s, &loop);
  emit_store_constant(s, 0, RTMP, 0);
  emit_add_constant(s, RTMP, RTMP, 8);
  emit_sub_constant(s, RTMP2, RTMP2, 8);
  emit_jcc32(s, JNE, &loop);

  emit_label(s, &done);
  if (size_reg == REG_NONE) {
    emit_mov64(s, RTMP2, payload_bytes + 8);
  } else {
    emit_sub_constant(s, RTMP2, size_reg, TAG_FIXNUM_VALUE(8));
    emit_sar_constant(s, RTMP2, RTMP2, FIXNUM_SHIFT);
    emit_add_constant(s, RTMP2, RTMP2, 8);
  }
  emit_sub(s, RTMP, RTMP, RTMP2);
}

/////////////////// memory

// Emit R15 twice, so we have an odd number - and therefore a balanced stack
static uint8_t const callee_save[] = {RBX, RBP, R12, R13, R14, R15, R15};
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
  emit_literal_constant(s, XO_MOVSD, hw_fpr(dst), idx);
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
