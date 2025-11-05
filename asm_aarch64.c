// Temporary AArch64 stubs to make the build succeed.

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "asm_aarch64.h"

extern uint8_t *p;

const char *const reg_names[MAX_REG] = {
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

static void bump(int64_t delta) { p -= delta; }

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

static void emit_op(uint32_t code) {
  p -= 4;
  memcpy(p, &code, 4);
}

void restore_callee_regs() { printf("TODO resotre callee save \n"); }

void save_callee_regs() { printf("TODO save callee save \n"); }

void emit_ret() { emit_op(0xD65F03C0); }

void emit_jmp32(int32_t offset) {
  int64_t delta = (int64_t)offset + 4;
  assert((delta & 0x3) == 0);
  int64_t imm26 = delta / 4;
  assert(imm26 >= -(1LL << 25) && imm26 < (1LL << 25));
  uint32_t opcode = 0x14000000u | ((uint32_t)imm26 & 0x03ffffffu);
  emit_op(opcode);
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

// Load a 64-bit constant into a register, mirroring GAS priority.
void emit_mov64(uint8_t rd, int64_t imm) {
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
      emit_op(movz_opcode(rd, 0, 0));
    } else {
      emit_op(movz_opcode(rd, chunks[idx], (uint8_t)idx));
    }
    return;
  }

  int nonffff = count_nonzero_chunks(nchunks);
  if (nonffff <= 1) {
    int idx = find_first_nonzero_index(nchunks);
    if (idx < 0) {
      emit_op(movn_opcode(rd, 0, 0));
    } else {
      emit_op(movn_opcode(rd, nchunks[idx], (uint8_t)idx));
    }
    return;
  }

  uint8_t N = 0;
  uint8_t immr = 0;
  uint8_t imms = 0;
  if (encode_logical_immediate64(value, &N, &immr, &imms)) {
    emit_op(orr_logical_immediate_opcode(rd, N, immr, imms));
    return;
  }

  int cost_z = nonzero;
  int cost_n = 1 + nonffff;
  if (cost_z <= cost_n) {
    int first = find_first_nonzero_index(chunks);
    assert(first >= 0);
    for (int i = 3; i >= 0; i--) {
      if (i == first) {
        continue;
      }
      if (chunks[i] != 0) {
        emit_op(movk_opcode(rd, chunks[i], (uint8_t)i));
      }
    }
    emit_op(movz_opcode(rd, chunks[first], (uint8_t)first));
  } else {
    int first = find_first_nonzero_index(nchunks);
    assert(first >= 0);
    for (int i = 3; i >= 0; i--) {
      if (i == first) {
        continue;
      }
      if (nchunks[i] != 0) {
        emit_op(movk_opcode(rd, nchunks[i], (uint8_t)i));
      }
    }
    emit_op(movn_opcode(rd, nchunks[first], (uint8_t)first));
  }
}

void emit_pop(uint8_t r) { printf("TODO pop \n"); }

void emit_push(uint8_t r) { printf("TODO push \n"); }

void emit_mem_reg(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2) {
  printf("TODO emit_mem_reg \n");
}

void emit_reg_reg(uint8_t opcode, uint8_t src, uint8_t dst) {
  printf("TODO emit_reg_reg \n");
}

void emit_jcc32(enum jcc_cond cond, int64_t offset) {
  printf("TODO emit_jcc32 \n");
}
