// Temporary AArch64 stubs to make the build succeed.

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "asm.h"

static inline uint8_t hw_fpr(uint8_t reg) {
  assert(reg >= FPR_REG_START && reg < AARCH64_MAX_REG);
  return reg - FPR_REG_START;
}

const char *const reg_names[AARCH64_MAX_REG] = {
#define X(name) #name,
    ASM_AARCH64_REGISTER_LIST(X)
#undef X
#define X(name) #name,
        ASM_AARCH64_FREGISTER_LIST(X)
#undef X
};

void asm_mark_unallocatable(bool used[MAX_REG]) {
  used[SP] = true;
  used[FP] = true;
  used[LR] = true;
  used[RTMP] = true;
  used[RSTACK] = true;
  used[RSTATE] = true;
  used[X16] = true;
  used[X17] = true;
  used[X18] = true;
}

bool asm_is_callee_saved(uint8_t reg) {
  switch (reg) {
  case X19:
  case X20:
  case X21:
  case X22:
  case X23:
  case X24:
  case X25:
  case X26:
  case X27:
  case X28:
  case FP:
  case LR:
  case V8:
  case V9:
  case V10:
  case V11:
  case V12:
  case V13:
  case V14:
  case V15:
    return true;
  default:
    return false;
  }
}

static uint64_t count_trailing_zeros64(uint64_t n) {
  if (n == 0) {
    return 64;
  }
  return (uint64_t)__builtin_ctzll(n);
}

static uint64_t count_leading_zeros64(uint64_t n) {
  if (n == 0) {
    return 64;
  }
  return (uint64_t)__builtin_clzll(n);
}

static uint64_t rotate_right64(uint64_t v, uint64_t n) {
  uint64_t shift = n & 63;
  if (shift == 0) {
    return v;
  }
  return (v >> shift) | (v << (64 - shift));
}

static uint64_t clear_trailing_ones64(uint64_t n) { return n & (n + 1); }

// Try to encode a 64-bit logical immediate (bitmask) as N:immr:imms.
// See Arm ARM section on logical immediates for details on the repeating
// zero/one pattern encoding.
//
// https://dougallj.wordpress.com/2021/10/30/bit-twiddling-optimising-aarch64-logical-immediate-encoding-and-decoding/
static bool encode_logical_immediate64(uint64_t val, uint8_t *N, uint8_t *immr,
                                       uint8_t *imms) {
  assert(N);
  assert(immr);
  assert(imms);
  if (val == 0 || val == UINT64_MAX) {
    return false;
  }

  uint64_t rotation = count_trailing_zeros64(clear_trailing_ones64(val));
  uint64_t normalized = rotate_right64(val, rotation & 63);
  uint64_t zeroes = count_leading_zeros64(normalized);
  uint64_t ones = count_trailing_zeros64(~normalized);
  uint64_t size = zeroes + ones;

  if (size == 0 || size > 64) {
    return false;
  }
  if (rotate_right64(val, size & 63) != val) {
    return false;
  }
  if ((size & (size - 1)) != 0) {
    return false;
  }

  uint64_t mask = (size == 64) ? 63 : (size - 1);
  uint8_t immr_val = (uint8_t)(((-((int64_t)rotation)) & mask) & UINT8_C(0x3F));
  int64_t imms_expr = (-((int64_t)size * 2)) | ((int64_t)ones - 1);
  uint8_t imms_val = (uint8_t)(imms_expr & UINT8_C(0x3F));
  uint8_t N_val = (uint8_t)(size >> 6);

  *N = N_val;
  *immr = immr_val;
  *imms = imms_val;
  return true;
}

static uint8_t *emit_op(emit_state *s, uint32_t code) {
  return emit_imm32(s, code);
}

static uint32_t stp_pre(uint8_t rt, uint8_t rt2, uint8_t rn, int32_t offset) {
  assert((offset % 8) == 0);
  int32_t imm = offset / 8;
  assert(imm >= -64 && imm <= 63);
  uint32_t imm7 = (uint32_t)(imm & 0x7f);
  return 0xA9800000U | (imm7 << 15) | ((uint32_t)rt2 << 10) |
         ((uint32_t)rn << 5) | (uint32_t)rt;
}

static uint32_t ldp_post(uint8_t rt, uint8_t rt2, uint8_t rn, int32_t offset) {
  assert((offset % 8) == 0);
  int32_t imm = offset / 8;
  assert(imm >= -64 && imm <= 63);
  uint32_t imm7 = (uint32_t)(imm & 0x7f);
  return 0xA8C00000U | (imm7 << 15) | ((uint32_t)rt2 << 10) |
         ((uint32_t)rn << 5) | (uint32_t)rt;
}

static const struct {
  uint8_t r1, r2;
} callee_saved_pairs[] = {
    {X27, X28}, {X25, X26}, {X23, X24}, {X21, X22}, {X19, X20}, {FP, LR},
};

static uint32_t stp_pre_q(uint8_t rt, uint8_t rt2, uint8_t rn, int32_t offset) {
  assert(rt >= FPR_REG_START && rt < AARCH64_MAX_REG);
  assert(rt2 >= FPR_REG_START && rt2 < AARCH64_MAX_REG);
  uint8_t rt_hw = hw_fpr(rt);
  uint8_t rt2_hw = hw_fpr(rt2);
  assert((offset % 16) == 0);
  int32_t imm = offset / 16;
  assert(imm >= -64 && imm <= 63);
  uint32_t imm7 = (uint32_t)(imm & 0x7f);
  return 0xAD800000U | (imm7 << 15) | ((uint32_t)rt2_hw << 10) |
         ((uint32_t)rn << 5) | (uint32_t)rt_hw;
}

static uint32_t ldp_post_q(uint8_t rt, uint8_t rt2, uint8_t rn,
                           int32_t offset) {
  assert(rt >= FPR_REG_START && rt < AARCH64_MAX_REG);
  assert(rt2 >= FPR_REG_START && rt2 < AARCH64_MAX_REG);
  uint8_t rt_hw = hw_fpr(rt);
  uint8_t rt2_hw = hw_fpr(rt2);
  assert((offset % 16) == 0);
  int32_t imm = offset / 16;
  assert(imm >= -64 && imm <= 63);
  uint32_t imm7 = (uint32_t)(imm & 0x7f);
  return 0xACC00000U | (imm7 << 15) | ((uint32_t)rt2_hw << 10) |
         ((uint32_t)rn << 5) | (uint32_t)rt_hw;
}

static const struct {
  uint8_t r1, r2;
} callee_saved_fp_pairs[] = {
    {V8, V9},
    {V10, V11},
    {V12, V13},
    {V14, V15},
};

void restore_callee_regs(emit_state *s) {
  for (size_t i = 0;
       i < sizeof(callee_saved_pairs) / sizeof(callee_saved_pairs[0]); i++) {
    const size_t j = (sizeof(callee_saved_pairs) /
                      sizeof(callee_saved_pairs[0])) -
                     1 - i;
    emit_op(s, ldp_post(callee_saved_pairs[j].r1, callee_saved_pairs[j].r2, SP,
                        16));
  }
  for (size_t i = 0;
       i < sizeof(callee_saved_fp_pairs) / sizeof(callee_saved_fp_pairs[0]);
       i++) {
    const size_t j = (sizeof(callee_saved_fp_pairs) /
                      sizeof(callee_saved_fp_pairs[0])) -
                     1 - i;
    emit_op(s, ldp_post_q(callee_saved_fp_pairs[j].r1,
                          callee_saved_fp_pairs[j].r2, SP, 32));
  }
}

void save_callee_regs(emit_state *s) {
  for (size_t i = 0;
       i < sizeof(callee_saved_fp_pairs) / sizeof(callee_saved_fp_pairs[0]);
       i++) {
    emit_op(s, stp_pre_q(callee_saved_fp_pairs[i].r1,
                         callee_saved_fp_pairs[i].r2, SP, -32));
  }
  for (size_t i = 0;
       i < sizeof(callee_saved_pairs) / sizeof(callee_saved_pairs[0]); i++) {
    emit_op(s, stp_pre(callee_saved_pairs[i].r1, callee_saved_pairs[i].r2, SP,
                       -16));
  }
}

void emit_ret(emit_state *s) { emit_op(s, 0xD65F03C0); }

void emit_jmp32(emit_state *s, int64_t target) {
  int64_t delta = target - emit_offset(s);
  assert((delta & 0x3) == 0);
  int64_t imm26 = delta / 4;
  assert(imm26 >= -(1LL << 25) && imm26 < (1LL << 25));
  uint32_t opcode = 0x14000000U | ((uint32_t)imm26 & 0x03ffffffU);
  emit_op(s, opcode);
}

void emit_jmp32_patch_there(emit_state *s, int64_t patch, int64_t target) {
  assert(patch);
  int64_t delta = target - patch;
  assert((delta & 0x3) == 0);
  int64_t imm26 = delta / 4;
  assert(imm26 >= -(1LL << 25) && imm26 < (1LL << 25));
  uint32_t opcode = 0x14000000U | ((uint32_t)imm26 & 0x03ffffffU);
  memcpy((void *)patch, &opcode, sizeof(opcode));
}
void emit_jmp32_patch_here(emit_state *s, int64_t patch) {
  emit_jmp32_patch_there(s, patch, emit_offset(s));
}

void emit_jcc32(emit_state *s, enum jcc_cond cond, int64_t target) {
  if (cond == JP) {
    abort();
  }
  uint8_t arm_cond = (uint8_t)cond;
  assert(arm_cond <= 0xf);
  int64_t delta = target - emit_offset(s);
  assert((delta & 0x3) == 0);
  int64_t imm19 = delta / 4;
  assert(imm19 >= -(1LL << 18) && imm19 < (1LL << 18));
  uint32_t opcode =
      0x54000000U | (((uint32_t)imm19 & 0x7ffffU) << 5) | (uint32_t)arm_cond;
  emit_op(s, opcode);
}
static uint32_t movz_opcode(uint8_t rd, uint16_t imm16, uint8_t chunk) {
  assert(rd < 31);
  assert(chunk < 4);
  uint32_t hw = chunk & 0x3;
  return 0xD2800000U | (hw << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}

static uint32_t movn_opcode(uint8_t rd, uint16_t imm16, uint8_t chunk) {
  assert(rd < 31);
  assert(chunk < 4);
  uint32_t hw = chunk & 0x3;
  return 0x92800000U | (hw << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}

static uint32_t movk_opcode(uint8_t rd, uint16_t imm16, uint8_t chunk) {
  assert(rd < 31);
  assert(chunk < 4);
  uint32_t hw = chunk & 0x3;
  return 0xF2800000U | (hw << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}

static uint32_t orr_logical_immediate_opcode(uint8_t rd, uint8_t N,
                                             uint8_t immr, uint8_t imms) {
  assert(rd < 31);
  return 0xB2000000U | ((uint32_t)N << 22) | ((uint32_t)immr << 16) |
         ((uint32_t)imms << 10) | (31U << 5) | (uint32_t)rd;
}

static bool encode_subs_immediate(int64_t imm, uint32_t *shift,
                                  uint32_t *imm12) {
  assert(shift);
  assert(imm12);
  if (imm < 0) {
    return false;
  }
  uint64_t uimm = (uint64_t)imm;
  if (uimm <= UINT64_C(0xFFF)) {
    *shift = 0;
    *imm12 = (uint32_t)uimm;
    return true;
  }
  if ((uimm & UINT64_C(0xFFF)) == 0) {
    uint64_t shifted = uimm >> 12;
    if (shifted <= UINT64_C(0xFFF)) {
      *shift = 1;
      *imm12 = (uint32_t)shifted;
      return true;
    }
  }
  return false;
}

static int count_nonzero_chunks(const uint16_t *chunks) {
  int count = 0;
  for (int i = 0; i < 4; i++) {
    if (chunks[i] != 0) {
      count++;
    }
  }
  return count;
}

static int find_first_nonzero_index(const uint16_t *chunks) {
  for (int i = 0; i < 4; i++) {
    if (chunks[i] != 0) {
      return i;
    }
  }
  return -1;
}

static void emit_mov_sequence(emit_state *s, uint8_t rd, const uint16_t *chunks,
                              bool use_movn) {
  int first = find_first_nonzero_index(chunks);
  assert(first >= 0);
  for (int i = 3; i >= 0; i--) {
    if (i == first) {
      continue;
    }
    if (chunks[i] != 0) {
      emit_op(s, movk_opcode(rd, chunks[i], (uint8_t)i));
    }
  }
  if (use_movn) {
    emit_op(s, movn_opcode(rd, chunks[first], (uint8_t)first));
  } else {
    emit_op(s, movz_opcode(rd, chunks[first], (uint8_t)first));
  }
}

// Load a 64-bit constant into a register, mirroring GAS priority.
void emit_mov64(emit_state *s, uint8_t rd, int64_t imm) {
  assert(rd < 31);
  uint64_t value = (uint64_t)imm;

  uint16_t chunks[4];
  uint16_t nchunks[4];
  for (int i = 0; i < 4; i++) {
    chunks[i] = (uint16_t)((value >> (i * 16)) & 0xFFFF);
    nchunks[i] = (uint16_t)(~chunks[i] & 0xFFFF);
  }

  int nonzero = count_nonzero_chunks(chunks);
  if (nonzero <= 1) {
    int idx = find_first_nonzero_index(chunks);
    if (idx < 0) {
      emit_op(s, movz_opcode(rd, 0, 0));
    } else {
      emit_op(s, movz_opcode(rd, chunks[idx], (uint8_t)idx));
    }
    return;
  }

  int nonffff = count_nonzero_chunks(nchunks);
  if (nonffff <= 1) {
    int idx = find_first_nonzero_index(nchunks);
    if (idx < 0) {
      emit_op(s, movn_opcode(rd, 0, 0));
    } else {
      emit_op(s, movn_opcode(rd, nchunks[idx], (uint8_t)idx));
    }
    return;
  }

  uint8_t N = 0;
  uint8_t immr = 0;
  uint8_t imms = 0;
  if (encode_logical_immediate64(value, &N, &immr, &imms)) {
    emit_op(s, orr_logical_immediate_opcode(rd, N, immr, imms));
    return;
  }

  int cost_z = nonzero;
  int cost_n = 1 + nonffff;
  if (cost_z <= cost_n) {
    emit_mov_sequence(s, rd, chunks, false);
  } else {
    emit_mov_sequence(s, rd, nchunks, true);
  }
}

void emit_call_reg(emit_state *s, uint8_t r) {
  assert(r < MAX_REG);
  uint32_t opcode = 0xD63F0000U | ((uint32_t)r << 5); // BLR Xr
  emit_op(s, opcode);
}

void emit_call32(emit_state *s, int64_t target) {
  int64_t delta = target - emit_offset(s);
  assert((delta & 0x3) == 0);
  int64_t imm26 = delta >> 2;
  assert(imm26 >= -(1 << 25) && imm26 <= ((1 << 25) - 1));
  uint32_t opcode = 0x94000000U | ((uint32_t)imm26 & UINT32_C(0x03FFFFFF));
  emit_op(s, opcode);
}

void emit_cmp(emit_state *s, uint8_t lhs, uint8_t rhs) {
  assert(lhs < FPR_REG_START);
  assert(rhs < FPR_REG_START);
  uint32_t opcode =
      0xEB000000U | ((uint32_t)rhs << 16) | ((uint32_t)lhs << 5) | UINT32_C(31);
  emit_op(s, opcode);
}

void emit_fcmp(emit_state *s, uint8_t lhs, uint8_t rhs) {
  assert(lhs >= FPR_REG_START && lhs < AARCH64_MAX_REG);
  assert(rhs >= FPR_REG_START && rhs < AARCH64_MAX_REG);
  uint32_t opcode = 0x1E602000U | ((uint32_t)hw_fpr(rhs) << 16) |
                    ((uint32_t)hw_fpr(lhs) << 5);
  emit_op(s, opcode);
}
void emit_fcmp_constant(emit_state *s, uint8_t reg, double imm) {
  assert(reg >= FPR_REG_START && reg < AARCH64_MAX_REG);
  load_constant(s, add_constant(s, imm), FRTMP);
  emit_fcmp(s, reg, FRTMP);
}

void emit_fmov_constant(emit_state *s, uint8_t dst, double imm) {
  assert(dst >= FPR_REG_START && dst < AARCH64_MAX_REG);
  load_constant(s, add_constant(s, imm), dst);
}
void emit_fmov(emit_state *s, uint8_t dst, uint8_t src) {
  assert(dst >= FPR_REG_START && dst < AARCH64_MAX_REG);
  assert(src >= FPR_REG_START && src < AARCH64_MAX_REG);
  uint32_t opcode =
      0x1E604000U | ((uint32_t)hw_fpr(src) << 5) | (uint32_t)hw_fpr(dst);
  emit_op(s, opcode);
}

void emit_cmp_constant(emit_state *s, uint8_t reg, int64_t imm) {
  assert(reg < FPR_REG_START);
  uint32_t shift = 0;
  uint32_t imm12 = 0;
  if (encode_subs_immediate(imm, &shift, &imm12)) {
    uint32_t opcode = 0xF1000000U | (shift << 22) | (imm12 << 10) |
                      ((uint32_t)reg << 5) | UINT32_C(31);
    emit_op(s, opcode);
    return;
  }
  emit_mov64(s, RTMP, imm);
  emit_cmp(s, reg, RTMP);
}

void emit_test_constant(emit_state *s, uint8_t reg, int64_t imm) {
  assert(reg < FPR_REG_START);
  uint8_t N = 0;
  uint8_t immr = 0;
  uint8_t imms = 0;
  if (!encode_logical_immediate64((uint64_t)imm, &N, &immr, &imms)) {
    abort();
  }
  uint32_t opcode = 0xF2000000U | ((uint32_t)N << 22) | ((uint32_t)immr << 16) |
                    ((uint32_t)imms << 10) | ((uint32_t)reg << 5) |
                    UINT32_C(31);
  emit_op(s, opcode);
}

void emit_and_constant(emit_state *s, uint8_t dst, uint8_t src, int64_t imm) {
  assert(dst < FPR_REG_START);
  assert(src < FPR_REG_START);
  uint8_t N = 0;
  uint8_t immr = 0;
  uint8_t imms = 0;
  if (!encode_logical_immediate64((uint64_t)imm, &N, &immr, &imms)) {
    abort();
  }
  uint32_t opcode = 0x92000000U | ((uint32_t)N << 22) | ((uint32_t)immr << 16) |
                    ((uint32_t)imms << 10) | ((uint32_t)src << 5) |
                    (uint32_t)dst;
  emit_op(s, opcode);
}

static void emit_add_sub(emit_state *s, uint32_t base, uint8_t dst, uint8_t lhs,
                         uint8_t rhs) {
  assert(dst < MAX_REG);
  assert(lhs < MAX_REG);
  assert(rhs < MAX_REG);
  uint32_t opcode =
      base | ((uint32_t)rhs << 16) | ((uint32_t)lhs << 5) | (uint32_t)dst;
  emit_op(s, opcode);
}

static void emit_add_sub_constant(emit_state *s, uint32_t base,
                                  uint32_t reg_base, uint8_t dst, uint8_t lhs,
                                  int64_t imm) {
  uint32_t shift = 0;
  uint32_t imm12 = 0;
  if (encode_subs_immediate(imm, &shift, &imm12)) {
    uint32_t opcode = base | (shift << 22) | (imm12 << 10) |
                      ((uint32_t)lhs << 5) | (uint32_t)dst;
    emit_op(s, opcode);
    return;
  }
  emit_mov64(s, RTMP, imm);
  emit_add_sub(s, reg_base, dst, lhs, RTMP);
}

void emit_add(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_add_sub(s, 0x8B000000U, dst, lhs, rhs);
}

void emit_add_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm) {
  assert(dst < MAX_REG);
  assert(lhs < MAX_REG);
  emit_add_sub_constant(s, 0x91000000U, 0x8B000000U, dst, lhs, imm);
}

void emit_sub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_add_sub(s, 0xCB000000U, dst, lhs, rhs);
}

void emit_sub_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm) {
  assert(dst < MAX_REG);
  assert(lhs < MAX_REG);
  emit_add_sub_constant(s, 0xD1000000U, 0xCB000000U, dst, lhs, imm);
}

void emit_fadd(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  assert(dst >= FPR_REG_START && dst < AARCH64_MAX_REG);
  assert(lhs >= FPR_REG_START && lhs < AARCH64_MAX_REG);
  assert(rhs >= FPR_REG_START && rhs < AARCH64_MAX_REG);
  uint32_t opcode = 0x1E602800U | ((uint32_t)hw_fpr(rhs) << 16) |
                    ((uint32_t)hw_fpr(lhs) << 5) | (uint32_t)hw_fpr(dst);
  emit_op(s, opcode);
}

void emit_fsub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  assert(dst >= FPR_REG_START && dst < AARCH64_MAX_REG);
  assert(lhs >= FPR_REG_START && lhs < AARCH64_MAX_REG);
  assert(rhs >= FPR_REG_START && rhs < AARCH64_MAX_REG);
  uint32_t opcode = 0x1E603800U | ((uint32_t)hw_fpr(rhs) << 16) |
                    ((uint32_t)hw_fpr(lhs) << 5) | (uint32_t)hw_fpr(dst);
  emit_op(s, opcode);
}

void emit_fadd_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  load_constant(s, add_constant(s, imm), FRTMP);
  emit_fadd(s, dst, lhs, FRTMP);
}

void emit_fsub_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  load_constant(s, add_constant(s, imm), FRTMP);
  emit_fsub(s, dst, lhs, FRTMP);
}

void emit_push(emit_state *s, uint8_t r) {
  assert(r < MAX_REG);
  emit_sub_constant(s, SP, SP, 16);
  emit_store(s, 0, SP, r);
}

void emit_pop(emit_state *s, uint8_t r) {
  assert(r < MAX_REG);
  emit_mem_load(s, 0, SP, r);
  emit_add_constant(s, SP, SP, 16);
}

void emit_debugtrap(emit_state *s) { emit_op(s, UINT32_C(0xD4200000)); }

typedef struct {
  uint8_t r1;
  uint8_t r2;
  bool fpr;
  bool pair;
} reg_op;

static size_t build_reg_ops(uint8_t const *regs, size_t count, reg_op *ops,
                            size_t max_ops) {
  size_t op_count = 0;
  size_t i = 0;
  while (i < count) {
    assert(op_count < max_ops);
    uint8_t r1 = regs[i];
    bool r1_is_fpr = (r1 >= FPR_REG_START);
    if (i + 1 < count) {
      uint8_t r2 = regs[i + 1];
      bool r2_is_fpr = (r2 >= FPR_REG_START);
      bool fpr_pair = r1_is_fpr && r2_is_fpr;
      bool gpr_pair = !r1_is_fpr && !r2_is_fpr;
      if (fpr_pair || gpr_pair) {
        ops[op_count++] =
            (reg_op){.r1 = r1, .r2 = r2, .fpr = r1_is_fpr, .pair = true};
        i += 2;
        continue;
      }
    }
    ops[op_count++] =
        (reg_op){.r1 = r1, .r2 = XZR, .fpr = r1_is_fpr, .pair = false};
    i += 1;
  }
  return op_count;
}

void emit_push_regs(emit_state *s, uint8_t const *regs, size_t count,
                    bool abi) {
  reg_op ops[MAX_REG];
  size_t op_count = build_reg_ops(regs, count, ops, MAX_REG);

  for (size_t i = 0; i < op_count; i++) {
    reg_op *op = &ops[i];
    if (op->pair) {
      if (op->fpr) {
        emit_op(s, stp_pre_q(op->r1, op->r2, SP, -32));
      } else {
        emit_op(s, stp_pre(op->r1, op->r2, SP, -16));
      }
      continue;
    }
    if (op->fpr) {
      emit_sub_constant(s, SP, SP, 16);
      emit_fstore(s, 0, SP, op->r1);
    } else {
      emit_op(s, stp_pre(op->r1, XZR, SP, -16));
    }
  }
  if (abi) {
    emit_op(s, stp_pre(FP, LR, SP, -16));
  }
}

void emit_pop_regs(emit_state *s, uint8_t const *regs, size_t count, bool abi) {
  reg_op ops[MAX_REG];
  size_t op_count = build_reg_ops(regs, count, ops, MAX_REG);

  if (abi) {
    emit_op(s, ldp_post(FP, LR, SP, 16));
  }
  for (size_t i = op_count; i > 0; i--) {
    reg_op *op = &ops[i - 1];
    if (op->pair) {
      if (op->fpr) {
        emit_op(s, ldp_post_q(op->r1, op->r2, SP, 32));
      } else {
        emit_op(s, ldp_post(op->r1, op->r2, SP, 16));
      }
      continue;
    }
    if (op->fpr) {
      emit_fmem_load(s, 0, SP, op->r1);
      emit_add_constant(s, SP, SP, 16);
    } else {
      emit_op(s, ldp_post(op->r1, XZR, SP, 16));
    }
  }
}

void emit_mov(emit_state *s, uint8_t dst, uint8_t src) {
  if (dst == src) {
    return;
  }
  assert(dst < MAX_REG);
  assert(src < MAX_REG);
  uint32_t opcode =
      0xAA0003E0U | ((uint32_t)src << 16) | (uint32_t)dst; // ORR Xd, XZR, Xm
  emit_op(s, opcode);
}
void emit_mem_load(emit_state *s, int32_t offset, uint8_t base, uint8_t dst) {
  assert(base < MAX_REG);
  assert(dst < MAX_REG);
  if ((offset % 8) == 0 && offset >= 0) {
    int32_t imm = offset / 8;
    assert(imm < 4096);
    uint32_t opcode = 0xF9400000U | ((uint32_t)imm << 10) |
                      ((uint32_t)base << 5) | (uint32_t)dst;
    emit_op(s, opcode);
    return;
  }
  assert(offset >= -256 && offset <= 255);
  uint32_t imm9 = (uint32_t)(offset & 0x1ff);
  uint32_t opcode =
      0xF8400000U | (imm9 << 12) | ((uint32_t)base << 5) | (uint32_t)dst;
  emit_op(s, opcode);
}

void emit_fmem_load(emit_state *s, int32_t offset, uint8_t base, uint8_t dst) {
  assert(base < FPR_REG_START);
  assert(dst >= FPR_REG_START && dst < AARCH64_MAX_REG);
  if ((offset % 8) == 0 && offset >= 0) {
    int32_t imm = offset / 8;
    assert(imm < 4096);
    uint32_t opcode = 0xFD400000U | ((uint32_t)imm << 10) |
                      ((uint32_t)base << 5) | (uint32_t)hw_fpr(dst);
    emit_op(s, opcode);
    return;
  }
  assert(offset >= -256 && offset <= 255);
  uint32_t imm9 = (uint32_t)(offset & 0x1ff);
  uint32_t opcode = 0xFC400000U | (imm9 << 12) | ((uint32_t)base << 5) |
                    (uint32_t)hw_fpr(dst);
  emit_op(s, opcode);
}

void emit_store(emit_state *s, int32_t offset, uint8_t base, uint8_t src) {
  assert(base < MAX_REG);
  assert(src < MAX_REG);
  if ((offset % 8) == 0 && offset >= 0) {
    int32_t imm = offset / 8;
    assert(imm < 4096);
    uint32_t opcode = 0xF9000000U | ((uint32_t)imm << 10) |
                      ((uint32_t)base << 5) | (uint32_t)src;
    emit_op(s, opcode);
    return;
  }
  assert(offset >= -256 && offset <= 255);
  uint32_t imm9 = (uint32_t)(offset & 0x1ff);
  uint32_t opcode =
      0xF8000000U | (imm9 << 12) | ((uint32_t)base << 5) | (uint32_t)src;
  emit_op(s, opcode);
}

void emit_fstore(emit_state *s, int32_t offset, uint8_t base, uint8_t src) {
  assert(base < FPR_REG_START);
  assert(src >= FPR_REG_START && src < AARCH64_MAX_REG);
  if ((offset % 8) == 0 && offset >= 0) {
    int32_t imm = offset / 8;
    assert(imm < 4096);
    uint32_t opcode = 0xFD000000U | ((uint32_t)imm << 10) |
                      ((uint32_t)base << 5) | (uint32_t)hw_fpr(src);
    emit_op(s, opcode);
    return;
  }
  assert(offset >= -256 && offset <= 255);
  uint32_t imm9 = (uint32_t)(offset & 0x1ff);
  uint32_t opcode = 0xFC000000U | (imm9 << 12) | ((uint32_t)base << 5) |
                    (uint32_t)hw_fpr(src);
  emit_op(s, opcode);
}

void emit_store_constant(emit_state *s, int32_t offset, uint8_t base,
                         int64_t value) {
  assert(base < MAX_REG);
  emit_mov64(s, RTMP, value);
  emit_store(s, offset, base, RTMP);
}

void asm_load_constant(emit_state *s, int idx, uint8_t dst) {
  assert(s);
  assert(dst >= FPR_REG_START && dst < AARCH64_MAX_REG);
  assert(idx >= 0);
  assert((size_t)idx < arrlen(s->const_pool));
  uint8_t *ldr_site =
      emit_op(s, 0xFD400000U | ((uint32_t)RTMP << 5) | (uint32_t)hw_fpr(dst));
  constant_entry *entry = &s->const_pool[idx];
  uint8_t *adrp_site =
      emit_op(s, 0x90000000U | ((uint32_t)RTMP << 5) | (uint32_t)RTMP);
  const_patch patch = {.inst0 = adrp_site, .inst1 = ldr_site};
  arrput(&s->z, entry->patches, patch);
}

void asm_patch_constant_pool(emit_state *s) {
  size_t len = arrlen(s->const_pool);
  for (size_t i = 0; i < len; i++) {
    constant_entry *entry = &s->const_pool[i];
    size_t patch_len = arrlen(entry->patches);
    for (size_t j = 0; j < patch_len; j++) {
      uint8_t *adrp_site = entry->patches[j].inst0;
      uint8_t *ldr_site = entry->patches[j].inst1;
      assert(adrp_site && ldr_site);

      uint64_t const_addr = (uint64_t)entry->addr;
      uint64_t pc = (uint64_t)adrp_site;
      int64_t page_delta =
          ((int64_t)(const_addr >> 12)) - ((int64_t)(pc >> 12));
      assert(page_delta >= -(1LL << 20) && page_delta < (1LL << 20));
      uint32_t immlo = (uint32_t)(page_delta & 0x3);
      uint32_t immhi = (uint32_t)((page_delta >> 2) & 0x7FFFF);
      uint32_t rd = (*((uint32_t *)adrp_site)) & 0x1F;
      uint32_t adrp = 0x90000000U | (immlo << 29) | (immhi << 5) | (rd & 0x1F);
      memcpy(adrp_site, &adrp, sizeof(adrp));

      uint64_t page_offset = const_addr & 0xFFFU;
      assert((page_offset & 0x7) == 0);
      uint32_t imm12 = (uint32_t)(page_offset >> 3);
      uint32_t orig = *((uint32_t *)ldr_site);
      uint32_t base = (orig >> 5) & 0x1F;
      uint32_t dst = orig & 0x1F;
      uint32_t ldr = 0xFD400000U | (imm12 << 10) | (base << 5) | (dst & 0x1F);
      memcpy(ldr_site, &ldr, sizeof(ldr));
    }
  }
}
