// Temporary AArch64 stubs to make the build succeed.

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asm.h"

const char *const reg_names[AARCH64_MAX_REG] = {
#define X(name) #name,
    ASM_AARCH64_REGISTER_LIST(X)
#undef X
};

void asm_mark_unallocatable(bool used[MAX_REG]) {
  used[SP] = true;
  used[FP] = true;
  used[LR] = true;
  used[RTMP] = true;
  used[RSTACK] = true;
  used[X16] = true;
  used[X17] = true;
  used[X18] = true;
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

#define p (s->p)
static void emit_op(emit_state *s, uint32_t code) {
  p -= 4;
  memcpy(p, &code, 4);
}

static uint32_t stp_pre(uint8_t rt, uint8_t rt2, uint8_t rn, int32_t offset) {
  assert((offset % 8) == 0);
  int32_t imm = offset / 8;
  assert(imm >= -64 && imm <= 63);
  uint32_t imm7 = (uint32_t)(imm & 0x7f);
  return 0xA9800000u | (imm7 << 15) | ((uint32_t)rt2 << 10) |
         ((uint32_t)rn << 5) | (uint32_t)rt;
}

static uint32_t ldp_post(uint8_t rt, uint8_t rt2, uint8_t rn, int32_t offset) {
  assert((offset % 8) == 0);
  int32_t imm = offset / 8;
  assert(imm >= -64 && imm <= 63);
  uint32_t imm7 = (uint32_t)(imm & 0x7f);
  return 0xA8C00000u | (imm7 << 15) | ((uint32_t)rt2 << 10) |
         ((uint32_t)rn << 5) | (uint32_t)rt;
}

static const struct {
  uint8_t r1, r2;
} callee_saved_pairs[] = {
    {X27, X28}, {X25, X26}, {X23, X24}, {X21, X22}, {X19, X20}, {FP, LR},
};

void restore_callee_regs(emit_state *s) {
  for (size_t i = 0; i < sizeof(callee_saved_pairs) / sizeof(callee_saved_pairs[0]);
       i++) {
    const size_t j =
        sizeof(callee_saved_pairs) / sizeof(callee_saved_pairs[0]) - 1 - i;
    emit_op(s, ldp_post(callee_saved_pairs[j].r1, callee_saved_pairs[j].r2, SP, 16));
  }
}

void save_callee_regs(emit_state *s) {
  for (size_t i = 0; i < sizeof(callee_saved_pairs) / sizeof(callee_saved_pairs[0]);
       i++) {
    emit_op(
        s, stp_pre(callee_saved_pairs[i].r1, callee_saved_pairs[i].r2, SP, -16));
  }
}

void emit_ret(emit_state *s) { emit_op(s, 0xD65F03C0); }

void emit_jmp32(emit_state *s, int64_t target) {
  int64_t delta = target - emit_offset(s);
  delta += 4;
  assert((delta & 0x3) == 0);
  int64_t imm26 = delta / 4;
  assert(imm26 >= -(1LL << 25) && imm26 < (1LL << 25));
  uint32_t opcode = 0x14000000u | ((uint32_t)imm26 & 0x03ffffffu);
  emit_op(s, opcode);
}

void emit_jmp32_patch_here(emit_state *s, int64_t patch) {
  assert(patch);
  int64_t target = emit_offset(s);
  int64_t delta = target - patch;
  assert((delta & 0x3) == 0);
  int64_t imm26 = delta / 4;
  assert(imm26 >= -(1LL << 25) && imm26 < (1LL << 25));
  uint32_t opcode = 0x14000000u | ((uint32_t)imm26 & 0x03ffffffu);
  memcpy((void *)patch, &opcode, sizeof(opcode));
}

void emit_jcc32(emit_state *s, enum jcc_cond cond, int64_t target) {
  if (cond == JP) {
    abort();
  }
  uint8_t arm_cond = (uint8_t)cond;
  assert(arm_cond <= 0xf);
  int64_t delta = target - emit_offset(s);
  delta += 4;
  assert((delta & 0x3) == 0);
  int64_t imm19 = delta / 4;
  assert(imm19 >= -(1LL << 18) && imm19 < (1LL << 18));
  uint32_t opcode =
      0x54000000u | (((uint32_t)imm19 & 0x7ffffu) << 5) | (uint32_t)arm_cond;
  emit_op(s, opcode);
}
static uint32_t movz_opcode(uint8_t rd, uint16_t imm16, uint8_t chunk) {
  assert(rd < 31);
  assert(chunk < 4);
  uint32_t hw = chunk & 0x3;
  return 0xD2800000u | (hw << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}

static uint32_t movn_opcode(uint8_t rd, uint16_t imm16, uint8_t chunk) {
  assert(rd < 31);
  assert(chunk < 4);
  uint32_t hw = chunk & 0x3;
  return 0x92800000u | (hw << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}

static uint32_t movk_opcode(uint8_t rd, uint16_t imm16, uint8_t chunk) {
  assert(rd < 31);
  assert(chunk < 4);
  uint32_t hw = chunk & 0x3;
  return 0xF2800000u | (hw << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}

static uint32_t orr_logical_immediate_opcode(uint8_t rd, uint8_t N,
                                             uint8_t immr, uint8_t imms) {
  assert(rd < 31);
  return 0xB2000000u | ((uint32_t)N << 22) | ((uint32_t)immr << 16) |
         ((uint32_t)imms << 10) | (31u << 5) | (uint32_t)rd;
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

static uint32_t cmp_opcode(enum cmp_kind kind) {
  switch (kind) {
  case CMP_EQ:
  case CMP_LT:
    return 0xEB000000u; // SUBS XZR, lhs, rhs (alias for CMP)
  default:
    abort();
  }
}

static uint32_t cmp_imm_opcode(enum cmp_kind kind) {
  switch (kind) {
  case CMP_EQ:
  case CMP_LT:
    return 0xF1000000u; // SUBS XZR, reg, #imm (alias for CMP)
  default:
    abort();
  }
}

void emit_cmp(emit_state *s, enum cmp_kind kind, uint8_t lhs, uint8_t rhs) {
  assert(lhs < MAX_REG);
  assert(rhs < MAX_REG);
  uint32_t base = cmp_opcode(kind);
  uint32_t opcode =
      base | ((uint32_t)rhs << 16) | ((uint32_t)lhs << 5) | UINT32_C(31);
  emit_op(s, opcode);
}

void emit_cmp_constant(emit_state *s, enum cmp_kind kind, uint8_t reg,
                       int64_t imm) {
  assert(reg < MAX_REG);
  uint32_t shift = 0;
  uint32_t imm12 = 0;
  if (encode_subs_immediate(imm, &shift, &imm12)) {
    uint32_t opcode = cmp_imm_opcode(kind) | (shift << 22) | (imm12 << 10) |
                      ((uint32_t)reg << 5) | UINT32_C(31);
    emit_op(s, opcode);
    return;
  }
  emit_cmp(s, kind, reg, RTMP);
  emit_mov64(s, RTMP, imm);
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
  emit_add_sub(s, reg_base, dst, lhs, RTMP);
  emit_mov64(s, RTMP, imm);
}

void emit_add(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_add_sub(s, 0x8B000000u, dst, lhs, rhs);
}

void emit_add_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm) {
  assert(dst < MAX_REG);
  assert(lhs < MAX_REG);
  emit_add_sub_constant(s, 0x91000000u, 0x8B000000u, dst, lhs, imm);
}

void emit_sub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_add_sub(s, 0xCB000000u, dst, lhs, rhs);
}

void emit_sub_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm) {
  assert(dst < MAX_REG);
  assert(lhs < MAX_REG);
  emit_add_sub_constant(s, 0xD1000000u, 0xCB000000u, dst, lhs, imm);
}

void emit_mov(emit_state *s, uint8_t dst, uint8_t src) {
  assert(dst < MAX_REG);
  assert(src < MAX_REG);
  uint32_t opcode =
      0xAA0003E0u | ((uint32_t)src << 16) | (uint32_t)dst; // ORR Xd, XZR, Xm
  emit_op(s, opcode);
}
void emit_mem_load(emit_state *s, int32_t offset, uint8_t base, uint8_t dst) {
  assert(base < MAX_REG);
  assert(dst < MAX_REG);
  if ((offset % 8) == 0 && offset >= 0) {
    int32_t imm = offset / 8;
    assert(imm < 4096);
    uint32_t opcode = 0xF9400000u | ((uint32_t)imm << 10) |
                      ((uint32_t)base << 5) | (uint32_t)dst;
    emit_op(s, opcode);
    return;
  }
  assert(offset >= -256 && offset <= 255);
  uint32_t imm9 = (uint32_t)(offset & 0x1ff);
  uint32_t opcode =
      0xF8400000u | (imm9 << 12) | ((uint32_t)base << 5) | (uint32_t)dst;
  emit_op(s, opcode);
}

void emit_store(emit_state *s, int32_t offset, uint8_t base, uint8_t src) {
  assert(base < MAX_REG);
  assert(src < MAX_REG);
  if ((offset % 8) == 0 && offset >= 0) {
    int32_t imm = offset / 8;
    assert(imm < 4096);
    uint32_t opcode = 0xF9000000u | ((uint32_t)imm << 10) |
                      ((uint32_t)base << 5) | (uint32_t)src;
    emit_op(s, opcode);
    return;
  }
  assert(offset >= -256 && offset <= 255);
  uint32_t imm9 = (uint32_t)(offset & 0x1ff);
  uint32_t opcode =
      0xF8000000u | (imm9 << 12) | ((uint32_t)base << 5) | (uint32_t)src;
  emit_op(s, opcode);
}

void emit_store_constant(emit_state *s, int32_t offset, uint8_t base,
                         int64_t value) {
  assert(base < MAX_REG);
  emit_store(s, offset, base, RTMP);
  emit_mov64(s, RTMP, value);
}
