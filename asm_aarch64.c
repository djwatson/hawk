#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "asm.h"
#include "types.h"

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
static uint32_t encode_logical_immediate64(uint64_t val) {
  if (val == 0 || val == UINT64_MAX) return UINT32_MAX;

  uint64_t rotation = count_trailing_zeros64(clear_trailing_ones64(val));
  uint64_t normalized = rotate_right64(val, rotation & 63);
  uint64_t zeroes = count_leading_zeros64(normalized);
  uint64_t ones = count_trailing_zeros64(~normalized);
  uint64_t size = zeroes + ones;

  if (size == 0 || size > 64) return UINT32_MAX;
  if (rotate_right64(val, size & 63) != val) return UINT32_MAX;
  if ((size & (size - 1)) != 0) return UINT32_MAX;

  uint64_t mask = (size == 64) ? 63 : (size - 1);
  uint32_t immr = (uint32_t)(-((int64_t)rotation) & mask);
  int64_t imms_expr = (-((int64_t)size * 2)) | ((int64_t)ones - 1);
  uint32_t imms = (uint32_t)imms_expr & 63;
  return ((uint32_t)(size >> 6) << 22) | (immr << 16) | (imms << 10);
}

static uint32_t encode_fmov_double(double value) {
  uint64_t bits;
  memcpy(&bits, &value, sizeof(bits));
  for (uint32_t imm = 0; imm <= UINT8_MAX; imm++) {
    uint64_t b = (imm >> 6) & 1;
    uint64_t exponent = ((b ^ 1) << 10) | (b * UINT64_C(0x3fc)) |
                        ((imm >> 4) & 3);
    uint64_t expanded = ((uint64_t)(imm & 0x80) << 56) | (exponent << 52) |
                        ((uint64_t)(imm & 15) << 48);
    if (expanded == bits) return imm;
  }
  return UINT32_MAX;
}

static uint8_t *emit_op(emit_state *s, uint32_t code) {
  return emit_imm32(s, code);
}

enum a64_ins : uint32_t {
  A64_ADD = 0x8B000000U,
  A64_ADDI = 0x91000000U,
  A64_ADDS = 0xAB000000U,
  A64_ADDSI = 0xB1000000U,
  A64_ADRP = 0x90000000U,
  A64_ANDI = 0x92000000U,
  A64_ANDSI = 0xF2000000U,
  A64_ASR = 0x9340FC00U,
  A64_B = 0x14000000U,
  A64_BCC = 0x54000000U,
  A64_BL = 0x94000000U,
  A64_BLR = 0xD63F0000U,
  A64_BRK = 0xD4200000U,
  A64_CMP = 0xEB00001FU,
  A64_FADD = 0x1E602800U,
  A64_FCMP = 0x1E602000U,
  A64_FCVT_DS = 0x9E620000U,
  A64_FCVT_SD = 0x9E780000U,
  A64_FDIV = 0x1E601800U,
  A64_FMOV = 0x1E604000U,
  A64_FMOVI = 0x1E601000U,
  A64_FMUL = 0x1E600800U,
  A64_FRINTZ = 0x1E65C000U,
  A64_FSQRT = 0x1E61C000U,
  A64_FSUB = 0x1E603800U,
  A64_LDPX = 0xA9400000U,
  A64_LDPX_POST = 0xA8C00000U,
  A64_LDPQ_POST = 0xACC00000U,
  A64_LDRB = 0x39400000U,
  A64_LDRB_INDEXED = 0x38606800U,
  A64_LDRB_UNSCALED = 0x38400000U,
  A64_LDRD = 0xFD400000U,
  A64_LDRD_INDEXED = 0xFC606800U,
  A64_LDRD_UNSCALED = 0xFC400000U,
  A64_LDRX = 0xF9400000U,
  A64_LDRX_INDEXED = 0xF8606800U,
  A64_LDRX_UNSCALED = 0xF8400000U,
  A64_LSL = 0xD3400000U,
  A64_MOV = 0xAA0003E0U,
  A64_MOVK = 0xF2800000U,
  A64_MOVN = 0x92800000U,
  A64_MOVZ = 0xD2800000U,
  A64_MSUB = 0x9B008000U,
  A64_MUL = 0x9B007C00U,
  A64_ORRI = 0xB2000000U,
  A64_RET = 0xD65F03C0U,
  A64_SDIV = 0x9AC00C00U,
  A64_SMULH = 0x9B407C00U,
  A64_STPQ_PRE = 0xAD800000U,
  A64_STPX = 0xA9000000U,
  A64_STPX_PRE = 0xA9800000U,
  A64_STRB = 0x39000000U,
  A64_STRB_INDEXED = 0x38206800U,
  A64_STRB_UNSCALED = 0x38000000U,
  A64_STRD = 0xFD000000U,
  A64_STRD_INDEXED = 0xFC206800U,
  A64_STRD_UNSCALED = 0xFC000000U,
  A64_STRX = 0xF9000000U,
  A64_STRX_INDEXED = 0xF8206800U,
  A64_STRX_UNSCALED = 0xF8000000U,
  A64_SUB = 0xCB000000U,
  A64_SUBI = 0xD1000000U,
  A64_SUBS = 0xEB000000U,
  A64_SUBSI = 0xF1000000U,
};

#define A64_D(r) ((uint32_t)(r))
#define A64_N(r) ((uint32_t)(r) << 5)
#define A64_A(r) ((uint32_t)(r) << 10)
#define A64_M(r) ((uint32_t)(r) << 16)
#define A64_IMM12(n) ((uint32_t)(n) << 10)

static uint8_t hw_gpr(uint8_t reg) {
  assert(reg < FPR_REG_START);
  return reg;
}

static uint8_t hw_fpr(uint8_t reg) {
  assert(reg >= FPR_REG_START && reg < AARCH64_MAX_REG);
  return reg - FPR_REG_START;
}

static void emit_dnm(emit_state *s, uint32_t op, uint8_t rd, uint8_t rn,
                     uint8_t rm) {
  emit_op(s, op | A64_D(rd) | A64_N(rn) | A64_M(rm));
}

static void emit_dn(emit_state *s, uint32_t op, uint8_t rd, uint8_t rn) {
  emit_op(s, op | A64_D(rd) | A64_N(rn));
}

static void emit_nm(emit_state *s, uint32_t op, uint8_t rn, uint8_t rm) {
  emit_op(s, op | A64_N(rn) | A64_M(rm));
}

static uint8_t pick_addr_tmp(uint8_t reg0, uint8_t reg1) {
  if (RTMP != reg0 && RTMP != reg1) {
    return RTMP;
  }
  if (RTMP2 != reg0 && RTMP2 != reg1) {
    return RTMP2;
  }
  if (X16 != reg0 && X16 != reg1) {
    return X16;
  }
  if (X17 != reg0 && X17 != reg1) {
    return X17;
  }
  abort();
}

static uint8_t pick_addr_tmp3(uint8_t reg0, uint8_t reg1, uint8_t reg2) {
  if (RTMP != reg0 && RTMP != reg1 && RTMP != reg2) return RTMP;
  if (RTMP2 != reg0 && RTMP2 != reg1 && RTMP2 != reg2) return RTMP2;
  if (X16 != reg0 && X16 != reg1 && X16 != reg2) return X16;
  if (X17 != reg0 && X17 != reg1 && X17 != reg2) return X17;
  abort();
}

static uint32_t pair_op(uint32_t op, uint8_t rt, uint8_t rt2, uint8_t rn,
                        int32_t offset, uint8_t scale) {
  int32_t size = 1 << scale;
  assert((offset % size) == 0);
  int32_t imm = offset / size;
  assert(imm >= -64 && imm <= 63);
  return op | ((uint32_t)(imm & 0x7f) << 15) | A64_A(rt2) | A64_N(rn) |
         A64_D(rt);
}

typedef struct {
  uint8_t r1, r2;
} reg_pair;

static const reg_pair callee_saved_pairs[] = {
    {X27, X28}, {X25, X26}, {X23, X24}, {X21, X22}, {X19, X20}, {FP, LR},
};

static const reg_pair callee_saved_fp_pairs[] = {
    {V8, V9},
    {V10, V11},
    {V12, V13},
    {V14, V15},
};

static void emit_pairs(emit_state *s, const reg_pair *pairs, size_t count,
                       uint32_t op, int32_t offset, uint8_t scale, bool fpr,
                       bool reverse) {
  for (size_t i = 0; i < count; i++) {
    const reg_pair *p = &pairs[reverse ? count - 1 - i : i];
    uint8_t r1 = fpr ? hw_fpr(p->r1) : hw_gpr(p->r1);
    uint8_t r2 = fpr ? hw_fpr(p->r2) : hw_gpr(p->r2);
    emit_op(s, pair_op(op, r1, r2, SP, offset, scale));
  }
}

void restore_callee_regs(emit_state *s) {
  emit_pairs(s, callee_saved_pairs, ARRAY_LEN(callee_saved_pairs),
             A64_LDPX_POST, 16, 3, false, true);
  emit_pairs(s, callee_saved_fp_pairs, ARRAY_LEN(callee_saved_fp_pairs),
             A64_LDPQ_POST, 32, 4, true, true);
}

void save_callee_regs(emit_state *s) {
  emit_pairs(s, callee_saved_fp_pairs, ARRAY_LEN(callee_saved_fp_pairs),
             A64_STPQ_PRE, -32, 4, true, false);
  emit_pairs(s, callee_saved_pairs, ARRAY_LEN(callee_saved_pairs), A64_STPX_PRE,
             -16, 3, false, false);
}

void emit_ret(emit_state *s) { emit_op(s, A64_RET); }

static uint32_t branch_imm(int64_t loc, int64_t target, uint8_t bits) {
  int64_t delta = target - loc;
  assert((delta & 3) == 0);
  int64_t imm = delta / 4;
  assert(imm >= -(INT64_C(1) << (bits - 1)));
  assert(imm < (INT64_C(1) << (bits - 1)));
  return (uint32_t)imm & ((UINT32_C(1) << bits) - 1);
}

void asm_patch_jmp32(emit_state *s, uint8_t *loc, uint8_t const *target) {
  (void)s;
  assert(loc);
  assert(target);
  uint32_t opcode = (*(uint32_t *)loc & UINT32_C(0xFC000000)) |
                    branch_imm((int64_t)loc, (int64_t)target, 26);
  memcpy(loc, &opcode, sizeof(opcode));
}

void asm_patch_jcc32(emit_state *s, uint8_t *loc, uint8_t const *target) {
  (void)s;
  assert(loc);
  assert(target);
  uint32_t inst = *(uint32_t *)loc;
  uint32_t opcode = (inst & UINT32_C(0xFF00001F)) |
                    (branch_imm((int64_t)loc, (int64_t)target, 19) << 5);
  memcpy(loc, &opcode, sizeof(opcode));
}

bool asm_jcc32_can_reach(uint8_t const *loc, uint8_t const *target) {
  int64_t delta = (int64_t)target - (int64_t)loc;
  if (delta & 3) return false;
  int64_t imm19 = delta / 4;
  return imm19 >= -(INT64_C(1) << 18) && imm19 < (INT64_C(1) << 18);
}

uint8_t *asm_jcc32_start(uint8_t *loc) { return loc; }

uint8_t *asm_jcc32_end(uint8_t *loc) { return loc + 4; }

void asm_write_jmp32_at(emit_state *s, uint8_t *loc, uint8_t const *target) {
  (void)s;
  assert(loc);
  assert(target);
  uint32_t opcode =
      A64_B | branch_imm((int64_t)loc, (int64_t)target, 26);
  memcpy(loc, &opcode, sizeof(opcode));
}

void asm_emit_jmp32_resolved(emit_state *s, uint8_t const *target) {
  emit_op(s, A64_B | branch_imm(emit_offset(s), (int64_t)target, 26));
}

uint8_t *asm_emit_jmp32_placeholder(emit_state *s) {
  return emit_op(s, A64_B);
}

void asm_emit_jcc32_resolved(emit_state *s, enum jcc_cond cond,
                             uint8_t const *target) {
  uint8_t arm_cond = (uint8_t)cond;
  assert(arm_cond <= 0xf);
  emit_op(s, A64_BCC |
                 (branch_imm(emit_offset(s), (int64_t)target, 19) << 5) |
                 arm_cond);
}

uint8_t *asm_emit_jcc32_placeholder(emit_state *s, enum jcc_cond cond) {
  uint8_t arm_cond = (uint8_t)cond;
  assert(arm_cond <= 0xf);
  return emit_op(s, A64_BCC | arm_cond);
}

static uint32_t mov_wide(uint32_t op, uint8_t rd, uint16_t imm16,
                         uint8_t chunk) {
  assert(rd < 31);
  assert(chunk < 4);
  return op | ((uint32_t)chunk << 21) | ((uint32_t)imm16 << 5) | A64_D(rd);
}

static uint16_t mov_wide_imm16(uint32_t op) {
  return (uint16_t)((op >> 5) & 0xffff);
}

static uint8_t mov_wide_shift(uint32_t op) {
  return (uint8_t)((op >> 21) & 0x3);
}

uint8_t *asm_emit_mov64_patchable(emit_state *s, uint8_t rd, int64_t imm) {
  assert(rd < 31);
  uint64_t value = (uint64_t)imm;
  uint8_t *loc = (uint8_t *)emit_offset(s);
  for (uint8_t i = 0; i < 4; i++)
    emit_op(s, mov_wide(i ? A64_MOVK : A64_MOVZ, rd,
                        (uint16_t)(value >> (i * 16)), i));
  return loc;
}

bool asm_mov64_patchable_is_live(uint8_t const *loc) {
  assert(loc);
  uint32_t const *ops = (uint32_t const *)loc;
  uint8_t rd = (uint8_t)(ops[0] & 31);
  for (uint8_t i = 0; i < 4; i++)
    if ((ops[i] & 0xff800000U) != (i ? A64_MOVK : A64_MOVZ) ||
        (ops[i] & 31) != rd || mov_wide_shift(ops[i]) != i)
      return false;
  return true;
}

int64_t asm_read_mov64_patchable(uint8_t const *loc) {
  assert(loc);
  assert(asm_mov64_patchable_is_live(loc));
  uint32_t const *ops = (uint32_t const *)loc;
  uint64_t value = 0;
  for (uint8_t i = 0; i < 4; i++)
    value |= (uint64_t)mov_wide_imm16(ops[i]) << (i * 16);
  return (int64_t)value;
}

void asm_patch_mov64_patchable(emit_state *s, uint8_t *loc, int64_t imm) {
  (void)s;
  assert(loc);
  assert(asm_mov64_patchable_is_live(loc));
  uint32_t *ops = (uint32_t *)loc;
  uint8_t rd = (uint8_t)(ops[0] & 31);
  uint64_t value = (uint64_t)imm;
  for (uint8_t i = 0; i < 4; i++)
    ops[i] = mov_wide(i ? A64_MOVK : A64_MOVZ, rd,
                      (uint16_t)(value >> (i * 16)), i);
}

static uint32_t orr_logical_immediate_opcode(uint8_t rd, uint32_t imm) {
  assert(rd < 31);
  return A64_ORRI | imm | A64_N(31) | A64_D(rd);
}

static bool encode_add_sub_immediate(uint64_t imm, uint32_t *shift,
                                     uint32_t *imm12) {
  assert(shift);
  assert(imm12);
  if (imm <= UINT64_C(0xFFF)) {
    *shift = 0;
    *imm12 = (uint32_t)imm;
    return true;
  }
  if ((imm & UINT64_C(0xFFF)) == 0) {
    uint64_t shifted = imm >> 12;
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
  if (use_movn) {
    emit_op(s, mov_wide(A64_MOVN, rd, chunks[first], (uint8_t)first));
  } else {
    emit_op(s, mov_wide(A64_MOVZ, rd, chunks[first], (uint8_t)first));
  }
  for (int i = 0; i < 4; i++) {
    if (i == first) {
      continue;
    }
    if (chunks[i] != 0) {
      emit_op(s, mov_wide(A64_MOVK, rd, chunks[i], (uint8_t)i));
    }
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
      emit_op(s, mov_wide(A64_MOVZ, rd, 0, 0));
    } else {
      emit_op(s, mov_wide(A64_MOVZ, rd, chunks[idx], (uint8_t)idx));
    }
    return;
  }

  int nonffff = count_nonzero_chunks(nchunks);
  if (nonffff <= 1) {
    int idx = find_first_nonzero_index(nchunks);
    if (idx < 0) {
      emit_op(s, mov_wide(A64_MOVN, rd, 0, 0));
    } else {
      emit_op(s, mov_wide(A64_MOVN, rd, nchunks[idx], (uint8_t)idx));
    }
    return;
  }

  uint32_t logical = encode_logical_immediate64(value);
  if (logical != UINT32_MAX) {
    emit_op(s, orr_logical_immediate_opcode(rd, logical));
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
  emit_op(s, A64_BLR | A64_N(hw_gpr(r)));
}

void emit_call32(emit_state *s, int64_t target) {
  emit_op(s, A64_BL | branch_imm(emit_offset(s), target, 26));
}

void emit_cmp(emit_state *s, uint8_t lhs, uint8_t rhs) {
  emit_nm(s, A64_CMP, hw_gpr(lhs), hw_gpr(rhs));
}

void emit_fcmp(emit_state *s, uint8_t lhs, uint8_t rhs) {
  emit_nm(s, A64_FCMP, hw_fpr(lhs), hw_fpr(rhs));
}
void emit_fcmp_constant(emit_state *s, uint8_t reg, double imm) {
  assert(reg >= FPR_REG_START && reg < AARCH64_MAX_REG);
  if (imm == 0.0) {
    emit_op(s, A64_FCMP | A64_N(hw_fpr(reg)) | 8);
    return;
  }
  load_constant(s, add_constant(s, imm), FRTMP);
  emit_fcmp(s, reg, FRTMP);
}

void emit_fmov_constant(emit_state *s, uint8_t dst, double imm) {
  assert(dst >= FPR_REG_START && dst < AARCH64_MAX_REG);
  uint32_t encoded = encode_fmov_double(imm);
  if (encoded != UINT32_MAX) {
    emit_op(s, A64_FMOVI | (encoded << 13) | A64_D(hw_fpr(dst)));
    return;
  }
  load_constant(s, add_constant(s, imm), dst);
}
void emit_fmov(emit_state *s, uint8_t dst, uint8_t src) {
  emit_dn(s, A64_FMOV, hw_fpr(dst), hw_fpr(src));
}
void emit_int64_to_double(emit_state *s, uint8_t dst, uint8_t src) {
  emit_dn(s, A64_FCVT_DS, hw_fpr(dst), hw_gpr(src));
}
void emit_double_to_int64_trunc(emit_state *s, uint8_t dst, uint8_t src) {
  emit_dn(s, A64_FCVT_SD, hw_gpr(dst), hw_fpr(src));
}
void emit_ftruncate(emit_state *s, uint8_t dst, uint8_t src) {
  emit_dn(s, A64_FRINTZ, hw_fpr(dst), hw_fpr(src));
}

void emit_fsqrt(emit_state *s, uint8_t dst, uint8_t src) {
  emit_dn(s, A64_FSQRT, hw_fpr(dst), hw_fpr(src));
}

void emit_cmp_constant(emit_state *s, uint8_t reg, int64_t imm) {
  assert(reg < FPR_REG_START);
  uint32_t shift = 0;
  uint32_t imm12 = 0;
  uint64_t magnitude = imm < 0 ? -(uint64_t)imm : (uint64_t)imm;
  if (encode_add_sub_immediate(magnitude, &shift, &imm12)) {
    uint32_t opcode =
        (imm < 0 ? A64_ADDSI : A64_SUBSI) | (shift << 22) |
        A64_IMM12(imm12) | A64_N(reg) | 31;
    emit_op(s, opcode);
    return;
  }
  uint8_t tmp = reg == RTMP ? RTMP2 : RTMP;
  emit_mov64(s, tmp, imm);
  emit_cmp(s, reg, tmp);
}

void emit_test_constant(emit_state *s, uint8_t reg, int64_t imm) {
  assert(reg < FPR_REG_START);
  uint32_t logical = encode_logical_immediate64((uint64_t)imm);
  if (logical == UINT32_MAX) abort();
  emit_op(s, A64_ANDSI | logical | A64_N(reg) | 31);
}

void emit_and_constant(emit_state *s, uint8_t dst, uint8_t src, int64_t imm) {
  assert(dst < FPR_REG_START);
  assert(src < FPR_REG_START);
  uint32_t logical = encode_logical_immediate64((uint64_t)imm);
  if (logical == UINT32_MAX) abort();
  emit_op(s, A64_ANDI | logical | A64_N(src) | A64_D(dst));
}

static void emit_add_sub(emit_state *s, uint32_t base, uint8_t dst, uint8_t lhs,
                         uint8_t rhs) {
  emit_dnm(s, base, hw_gpr(dst), hw_gpr(lhs), hw_gpr(rhs));
}

static void emit_smulh(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_add_sub(s, A64_SMULH, dst, lhs, rhs);
}

#define DEFINE_FIXNUM_ADD_SUB_GUARD_OVERFLOW(name, reg_opcode, imm_opcode,     \
                                             inverse_opcode, reg_base)        \
  void asm_emit_fixnum_##name##_guard_overflow(emit_state *s, uint8_t dst,     \
                                               uint8_t lhs, uint8_t rhs,       \
                                               label *overflow_target) {       \
    emit_add_sub(s, reg_opcode, dst, lhs, rhs);                                \
    emit_jcc32(s, JO, overflow_target);                                        \
  }                                                                            \
  void asm_emit_fixnum_##name##_constant_guard_overflow(                       \
      emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm,                    \
      label *overflow_target) {                                                \
    emit_add_sub_constant(s, imm_opcode, inverse_opcode, reg_base, dst, lhs,   \
                          imm);                                                \
    emit_jcc32(s, JO, overflow_target);                                        \
  }

static void emit_add_sub_constant(emit_state *s, uint32_t base,
                                  uint32_t inverse_base, uint32_t reg_base,
                                  uint8_t dst, uint8_t lhs, int64_t imm) {
  uint8_t rd = hw_gpr(dst);
  uint8_t rn = hw_gpr(lhs);
  uint32_t shift = 0;
  uint32_t imm12 = 0;
  uint64_t magnitude = imm < 0 ? -(uint64_t)imm : (uint64_t)imm;
  if (encode_add_sub_immediate(magnitude, &shift, &imm12)) {
    uint32_t opcode =
        (imm < 0 ? inverse_base : base) | (shift << 22) |
        A64_IMM12(imm12) | A64_N(rn) | A64_D(rd);
    emit_op(s, opcode);
    return;
  }
  uint8_t tmp = pick_addr_tmp(dst, lhs);
  emit_mov64(s, tmp, imm);
  emit_add_sub(s, reg_base, dst, lhs, tmp);
}

static void emit_sdiv(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_add_sub(s, A64_SDIV, dst, lhs, rhs);
}

static void emit_msub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs,
                      uint8_t acc) {
  emit_op(s, A64_MSUB | A64_D(hw_gpr(dst)) | A64_N(hw_gpr(lhs)) |
                 A64_M(hw_gpr(rhs)) | A64_A(hw_gpr(acc)));
}

void emit_add(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_add_sub(s, A64_ADD, dst, lhs, rhs);
}

void emit_add_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm) {
  emit_add_sub_constant(s, A64_ADDI, A64_SUBI, A64_ADD, dst, lhs, imm);
}

void emit_sub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_add_sub(s, A64_SUB, dst, lhs, rhs);
}

DEFINE_FIXNUM_ADD_SUB_GUARD_OVERFLOW(add, A64_ADDS, A64_ADDSI, A64_SUBSI,
                                     A64_ADDS)
DEFINE_FIXNUM_ADD_SUB_GUARD_OVERFLOW(sub, A64_SUBS, A64_SUBSI, A64_ADDSI,
                                     A64_SUBS)

void emit_mul(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_add_sub(s, A64_MUL, dst, lhs, rhs);
}

static inline void emit_fixnum_mul_guard_overflow_reg(emit_state *s,
                                                      uint8_t dst, uint8_t lhs,
                                                      uint8_t rhs,
                                                      label *overflow_target) {
  if (rhs == RTMP) {
    emit_mov(s, RTMP2, rhs);
    rhs = RTMP2;
  }
  emit_smulh(s, RTMP, lhs, rhs);
  emit_mul(s, dst, lhs, rhs);
  emit_sar_constant(s, RTMP2, dst, 63);
  emit_cmp(s, RTMP, RTMP2);
  emit_jcc32(s, JNE, overflow_target);
}

void asm_emit_fixnum_mul_guard_overflow(emit_state *s, uint8_t dst, uint8_t lhs,
                                        uint8_t rhs, label *overflow_target) {
  emit_fixnum_mul_guard_overflow_reg(s, dst, lhs, rhs, overflow_target);
}

void emit_mul_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm) {
  assert(dst < FPR_REG_START);
  assert(lhs < FPR_REG_START);
  if (imm == 0) {
    emit_mov64(s, dst, 0);
    return;
  }
  if (imm == 1) {
    if (dst != lhs) {
      emit_mov(s, dst, lhs);
    }
    return;
  }
  if (imm == 2) {
    emit_add(s, dst, lhs, lhs);
    return;
  }
  if (imm == -1) {
    emit_sub(s, dst, XZR, lhs);
    return;
  }
  if (imm > 0 && (((uint64_t)imm & ((uint64_t)imm - 1)) == 0)) {
    emit_shl_constant(s, dst, lhs, (uint8_t)__builtin_ctzll((uint64_t)imm));
    return;
  }
  uint8_t tmp = pick_addr_tmp(dst, lhs);
  emit_mov64(s, tmp, imm);
  emit_mul(s, dst, lhs, tmp);
}

void asm_emit_fixnum_mul_constant_guard_overflow(emit_state *s, uint8_t dst,
                                                 uint8_t lhs, int64_t imm,
                                                 label *overflow_target) {
  emit_mov64(s, RTMP2, imm);
  emit_fixnum_mul_guard_overflow_reg(s, dst, lhs, RTMP2, overflow_target);
}

#undef DEFINE_FIXNUM_ADD_SUB_GUARD_OVERFLOW

void emit_sar_constant(emit_state *s, uint8_t dst, uint8_t src, uint8_t imm) {
  assert(dst < FPR_REG_START);
  assert(src < FPR_REG_START);
  assert(imm < 64);
  uint32_t opcode = A64_ASR | A64_M(imm) | A64_N(src) | A64_D(dst);
  emit_op(s, opcode);
}

void emit_shl_constant(emit_state *s, uint8_t dst, uint8_t src, uint8_t imm) {
  assert(dst < FPR_REG_START);
  assert(src < FPR_REG_START);
  assert(imm < 64);
  if (imm == 0) {
    if (dst != src) {
      emit_mov(s, dst, src);
    }
    return;
  }
  uint32_t immr = (64U - (uint32_t)imm) & 63U;
  uint32_t imms = 63U - (uint32_t)imm;
  uint32_t opcode =
      A64_LSL | A64_M(immr) | A64_IMM12(imms) | A64_N(src) | A64_D(dst);
  emit_op(s, opcode);
}

void emit_mod(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  assert(dst < FPR_REG_START);
  assert(lhs < FPR_REG_START);
  assert(rhs < FPR_REG_START);

  // Preserve operands in dedicated scratch regs:
  //   RTMP2 = lhs, RTMP = rhs
  // then compute:
  //   dst = sdiv(RTMP2, RTMP)
  //   dst = msub(dst, RTMP, RTMP2) => RTMP2 - dst*RTMP
  if (rhs == RTMP2) {
    emit_mov(s, RTMP, rhs);
    emit_mov(s, RTMP2, lhs);
  } else {
    emit_mov(s, RTMP2, lhs);
    emit_mov(s, RTMP, rhs);
  }
  emit_sdiv(s, dst, RTMP2, RTMP);
  emit_msub(s, dst, dst, RTMP, RTMP2);
}

void emit_quotient(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  assert(dst < FPR_REG_START);
  assert(lhs < FPR_REG_START);
  assert(rhs < FPR_REG_START);

  // Inputs are tagged fixnums. Untag both, divide, then retag the quotient.
  if (rhs == RTMP2) {
    emit_mov(s, RTMP, rhs);
    emit_mov(s, RTMP2, lhs);
  } else {
    emit_mov(s, RTMP2, lhs);
    emit_mov(s, RTMP, rhs);
  }
  emit_sar_constant(s, RTMP2, RTMP2, 3);
  emit_sar_constant(s, RTMP, RTMP, 3);
  emit_sdiv(s, dst, RTMP2, RTMP);
  emit_shl_constant(s, dst, dst, 3);
}

void emit_sub_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm) {
  emit_add_sub_constant(s, A64_SUBI, A64_ADDI, A64_SUB, dst, lhs, imm);
}

static void emit_fp_binary(emit_state *s, uint32_t op, uint8_t dst,
                           uint8_t lhs, uint8_t rhs) {
  emit_dnm(s, op, hw_fpr(dst), hw_fpr(lhs), hw_fpr(rhs));
}

void emit_fadd(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_fp_binary(s, A64_FADD, dst, lhs, rhs);
}

void emit_fsub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_fp_binary(s, A64_FSUB, dst, lhs, rhs);
}

void emit_fmul(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_fp_binary(s, A64_FMUL, dst, lhs, rhs);
}

void emit_fdiv(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs) {
  emit_fp_binary(s, A64_FDIV, dst, lhs, rhs);
}

static void emit_fp_constant(emit_state *s, uint32_t op, uint8_t dst,
                             uint8_t lhs, double imm) {
  load_constant(s, add_constant(s, imm), FRTMP);
  emit_fp_binary(s, op, dst, lhs, FRTMP);
}

void emit_fadd_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  emit_fp_constant(s, A64_FADD, dst, lhs, imm);
}

void emit_fsub_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  emit_fp_constant(s, A64_FSUB, dst, lhs, imm);
}

void emit_fmul_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  emit_fp_constant(s, A64_FMUL, dst, lhs, imm);
}

void emit_fdiv_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm) {
  emit_fp_constant(s, A64_FDIV, dst, lhs, imm);
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

void emit_debugtrap(emit_state *s) { emit_op(s, A64_BRK); }

static void emit_regs(emit_state *s, uint8_t const *regs, size_t count,
                      bool abi, bool load) {
  if (abi && !load)
    emit_op(s, pair_op(A64_STPX_PRE, FP, LR, SP, -16, 3));
  size_t frame_slots = count + (count & 1);
  if (frame_slots && !load)
    emit_sub_constant(s, SP, SP, (int64_t)(frame_slots * 8));
  for (size_t i = 0; i < count; i++) {
    uint8_t reg = regs[i];
    if (reg == REG_NONE) continue;
    if (reg < FPR_REG_START && i + 1 < count) {
      uint8_t reg2 = regs[i + 1];
      if (reg2 != REG_NONE && reg2 < FPR_REG_START) {
        uint32_t op = load ? A64_LDPX : A64_STPX;
        emit_op(s, pair_op(op, reg, reg2, SP, (int32_t)(i * 8), 3));
        i++;
        continue;
      }
    }
    int32_t offset = (int32_t)(i * 8);
    if (reg >= FPR_REG_START)
      load ? emit_fmem_load(s, offset, SP, reg)
           : emit_fstore(s, offset, SP, reg);
    else
      load ? emit_mem_load(s, offset, SP, reg)
           : emit_store(s, offset, SP, reg);
  }
  if (frame_slots && load)
    emit_add_constant(s, SP, SP, (int64_t)(frame_slots * 8));
  if (abi && load)
    emit_op(s, pair_op(A64_LDPX_POST, FP, LR, SP, 16, 3));
}

void emit_push_regs(emit_state *s, uint8_t const *regs, size_t count,
                    bool abi) {
  emit_regs(s, regs, count, abi, false);
}

void emit_pop_regs(emit_state *s, uint8_t const *regs, size_t count, bool abi) {
  emit_regs(s, regs, count, abi, true);
}

void emit_mov(emit_state *s, uint8_t dst, uint8_t src) {
  if (dst == src) {
    return;
  }
  hw_gpr(dst);
  hw_gpr(src);
  if (dst == SP || src == SP) {
    emit_dn(s, A64_ADDI, dst, src);
    return;
  }
  emit_op(s, A64_MOV | A64_M(src) | A64_D(dst));
}

static void emit_lso(emit_state *s, uint32_t scaled, uint32_t unscaled,
                     uint8_t scale, int32_t offset, uint8_t base, uint8_t reg,
                     bool fpr) {
  uint8_t rn = hw_gpr(base);
  uint8_t rt = fpr ? hw_fpr(reg) : hw_gpr(reg);
  int32_t mask = (1 << scale) - 1;
  if (offset >= 0 && !(offset & mask)) {
    if (scale) assert(offset < (4096 << scale));
    if (offset < (4096 << scale)) {
      emit_op(s, scaled | A64_IMM12(offset >> scale) | A64_N(rn) | A64_D(rt));
      return;
    }
  }
  if (offset >= -256 && offset <= 255) {
    emit_op(s, unscaled | ((uint32_t)(offset & 0x1ff) << 12) | A64_N(rn) |
                   A64_D(rt));
    return;
  }
  uint8_t addr = pick_addr_tmp(base, fpr ? REG_NONE : reg);
  emit_add_constant(s, addr, base, offset);
  emit_op(s, scaled | A64_N(addr) | A64_D(rt));
}

#define DEFINE_LSO(name, scaled, unscaled, scale, fpr)                         \
  void name(emit_state *s, int32_t offset, uint8_t base, uint8_t reg) {        \
    emit_lso(s, scaled, unscaled, scale, offset, base, reg, fpr);              \
  }

DEFINE_LSO(emit_mem_load, A64_LDRX, A64_LDRX_UNSCALED, 3, false)
DEFINE_LSO(emit_mem_load_u8, A64_LDRB, A64_LDRB_UNSCALED, 0, false)
DEFINE_LSO(emit_fmem_load, A64_LDRD, A64_LDRD_UNSCALED, 3, true)
DEFINE_LSO(emit_store, A64_STRX, A64_STRX_UNSCALED, 3, false)
DEFINE_LSO(emit_store_u8, A64_STRB, A64_STRB_UNSCALED, 0, false)
DEFINE_LSO(emit_fstore, A64_STRD, A64_STRD_UNSCALED, 3, true)

#undef DEFINE_LSO

static void emit_lso_indexed(emit_state *s, uint32_t indexed,
                             uint32_t scaled, uint32_t unscaled, uint8_t scale,
                             int32_t offset, uint8_t base, uint8_t index,
                             uint8_t reg, bool fpr) {
  uint8_t rt = fpr ? hw_fpr(reg) : hw_gpr(reg);
  if (offset) {
    uint8_t addr = pick_addr_tmp3(base, index, fpr ? REG_NONE : reg);
    emit_add(s, addr, base, index);
    emit_lso(s, scaled, unscaled, scale, offset, addr, reg, fpr);
  } else {
    emit_op(s, indexed | A64_D(rt) | A64_N(hw_gpr(base)) |
                   A64_M(hw_gpr(index)));
  }
}

#define DEFINE_LSO_INDEXED(name, indexed, scaled, unscaled, scale, fpr)        \
  void name(emit_state *s, int32_t offset, uint8_t base, uint8_t index,        \
            uint8_t reg) {                                                     \
    emit_lso_indexed(s, indexed, scaled, unscaled, scale, offset, base, index, \
                     reg, fpr);                                                \
  }

DEFINE_LSO_INDEXED(emit_mem_load_indexed, A64_LDRX_INDEXED, A64_LDRX,
                   A64_LDRX_UNSCALED, 3, false)
DEFINE_LSO_INDEXED(emit_mem_load_u8_indexed, A64_LDRB_INDEXED, A64_LDRB,
                   A64_LDRB_UNSCALED, 0, false)
DEFINE_LSO_INDEXED(emit_fmem_load_indexed, A64_LDRD_INDEXED, A64_LDRD,
                   A64_LDRD_UNSCALED, 3, true)
DEFINE_LSO_INDEXED(emit_store_indexed, A64_STRX_INDEXED, A64_STRX,
                   A64_STRX_UNSCALED, 3, false)
DEFINE_LSO_INDEXED(emit_store_u8_indexed, A64_STRB_INDEXED, A64_STRB,
                   A64_STRB_UNSCALED, 0, false)
DEFINE_LSO_INDEXED(emit_fstore_indexed, A64_STRD_INDEXED, A64_STRD,
                   A64_STRD_UNSCALED, 3, true)

#undef DEFINE_LSO_INDEXED

void emit_mem_cmp_constant(emit_state *s, int32_t offset, uint8_t base,
                           int64_t value) {
  uint8_t tmp = pick_addr_tmp(base, REG_NONE);
  emit_mem_load(s, offset, base, tmp);
  emit_cmp_constant(s, tmp, value);
}

void emit_mem_cmp_u8_constant(emit_state *s, int32_t offset, uint8_t base,
                              uint8_t value) {
  uint8_t tmp = pick_addr_tmp(base, REG_NONE);
  emit_mem_load_u8(s, offset, base, tmp);
  emit_cmp_constant(s, tmp, value);
}

void emit_store_constant(emit_state *s, int32_t offset, uint8_t base,
                         int64_t value) {
  assert(base < MAX_REG);
  if (value == 0) {
    emit_store(s, offset, base, XZR);
    return;
  }
  uint8_t tmp = base == RTMP ? RTMP2 : RTMP;
  emit_mov64(s, tmp, value);
  emit_store(s, offset, base, tmp);
}

void emit_store_constant_indexed(emit_state *s, int32_t offset, uint8_t base,
                                 uint8_t index, int64_t value) {
  if (value == 0) {
    emit_store_indexed(s, offset, base, index, XZR);
    return;
  }
  uint8_t tmp = pick_addr_tmp(base, index);
  emit_mov64(s, tmp, value);
  emit_store_indexed(s, offset, base, index, tmp);
}

void emit_store_u8_constant(emit_state *s, int32_t offset, uint8_t base,
                            uint8_t value) {
  uint8_t tmp = XZR;
  if (value) {
    tmp = pick_addr_tmp(base, REG_NONE);
    emit_mov64(s, tmp, value);
  }
  emit_store_u8(s, offset, base, tmp);
}

void emit_store_u8_constant_indexed(emit_state *s, int32_t offset,
                                    uint8_t base, uint8_t index,
                                    uint8_t value) {
  uint8_t tmp = XZR;
  if (value) {
    tmp = pick_addr_tmp(base, index);
    emit_mov64(s, tmp, value);
  }
  emit_store_u8_indexed(s, offset, base, index, tmp);
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
  emit_store(s, 0, RTMP, XZR);
  emit_add_constant(s, RTMP, RTMP, 8);
  emit_sub_constant(s, RTMP2, RTMP2, 8);
  emit_cmp_constant(s, RTMP2, 0);
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

void asm_load_constant(emit_state *s, int idx, uint8_t dst) {
  assert(s);
  assert(dst >= FPR_REG_START && dst < AARCH64_MAX_REG);
  assert(idx >= 0);
  assert((size_t)idx < arrlen(s->const_pool));
  constant_entry *entry = &s->const_pool[idx];
  uint8_t *adrp_site = emit_op(s, A64_ADRP | A64_N(RTMP) | A64_D(RTMP));
  uint8_t *ldr_site =
      emit_op(s, A64_LDRD | A64_N(RTMP) | A64_D(hw_fpr(dst)));
  const_patch patch = {.inst0 = adrp_site, .inst1 = ldr_site};
  arrput(entry->patches, patch);
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
      uint32_t adrp =
          A64_ADRP | (immlo << 29) | (immhi << 5) | A64_D(rd);
      memcpy(adrp_site, &adrp, sizeof(adrp));

      uint64_t page_offset = const_addr & 0xFFFU;
      assert((page_offset & 0x7) == 0);
      uint32_t imm12 = (uint32_t)(page_offset >> 3);
      uint32_t orig = *((uint32_t *)ldr_site);
      uint32_t base = (orig >> 5) & 0x1F;
      uint32_t dst = orig & 0x1F;
      uint32_t ldr =
          A64_LDRD | A64_IMM12(imm12) | A64_N(base) | A64_D(dst);
      memcpy(ldr_site, &ldr, sizeof(ldr));
    }
  }
}
