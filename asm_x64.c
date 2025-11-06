// Copyright 2023 Dave Watson

#define _DEFAULT_SOURCE

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "asm_x64.h"

extern uint8_t *p;

const char *const reg_names[MAX_REG] = {
#define X(name) #name,
  ASM_X64_REGISTER_LIST(X)
#undef X
};

void asm_mark_unallocatable(bool used[MAX_REG]) {
  used[RSP] = true;
  used[RTMP] = true;
  used[RSTACK] = true;
}

static uint8_t low3bits(uint8_t r) { return 0x7 & r; }

uint8_t callee_save[] = {RBX, RBP, R12, R13, R14, R15};
/////////////////// instruction encoding

void emit_rex(uint8_t w, uint8_t r, uint8_t x, uint8_t b) {
  *(--p) = 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
}

void emit_modrm(uint8_t mod, uint8_t reg, uint8_t rm) {
  *(--p) = (mod << 6) | (reg << 3) | rm;
}

void emit_sib(uint8_t scale, uint8_t index, uint8_t base) {
  *(--p) = (scale << 6) | ((0x7 & index) << 3) | ((0x7 & base));
}

void emit_imm8(uint8_t imm) { *(--p) = imm; }

void emit_imm64(int64_t imm) {
  p -= sizeof(int64_t);
  memcpy(p, &imm, sizeof(imm));
}

void emit_imm32(int32_t imm) {
  p -= sizeof(int32_t);
  memcpy(p, &imm, sizeof(imm));
}

static bool fits_in_32(int64_t imm) { return imm & 0xffffffff00000000; }

void emit_mov64(uint8_t r, int64_t imm) {
  // Note that 'imm' isn't necessarily a number here,
  // so we can't narrow negative numbers.
#ifndef VALGRIND
  if (fits_in_32(imm)) {
#endif
    emit_imm64(imm);
    *(--p) = 0xb8 | (0x7 & r);
    emit_rex(1, 0, 0, r >> 3);
#ifndef VALGRIND
  } else {
    // Unfortunately valgrind doesn't like this:
    // We do *NOT* want to sign-extend here!
    emit_imm32((int32_t)imm);
    *(--p) = 0xb8 | (0x7 & r);
    if (r >> 3) {
      emit_rex(0, 0, 0, r >> 3);
    }
  }
#endif
}

void emit_call_indirect(uint8_t r) {
  emit_modrm(0x3, 0x2, 0x7 & r);
  *(--p) = 0xff;
  emit_rex(1, 0, 0, r >> 3);
}

void emit_call_indirect_mem(int32_t offset) {
  emit_imm32(offset);
  emit_modrm(0x00, 2, RBP);
  *(--p) = 0xff;
  emit_rex(1, 0, 0, 0);
}

void emit_call32(int32_t offset) {
  emit_imm32(offset);
  *(--p) = 0xe8;
}

void emit_ret() { *(--p) = 0xc3; }

// TODO(djwatson) clean this up.  THe main issue is REX needs W=0.
// Also check R1 does full checks for rsp/rbp
void emit_cmp_mem32_imm32(int32_t offset, uint8_t r1, int32_t imm) {
  emit_imm32(imm);
  assert(r1 != RSP);
  assert(r1 != RBP);
  uint8_t r2 = 0x7;

  if (offset == 0 && low3bits(r1) != RBP) {
    emit_modrm(0x0, r2, 0x7 & r1);
  } else if ((int32_t)((int8_t)offset) == offset) {
    *(--p) = (int8_t)offset;
    emit_modrm(0x1, r2, 0x7 & r1);
  } else {
    emit_imm32(offset);
    emit_modrm(0x2, r2, 0x7 & r1);
  }

  *(--p) = 0x81;
  emit_rex(0, 0, 0, r1 >> 3);
}
void emit_cmp_reg_imm32(uint8_t r, int32_t imm) {
  if ((int32_t)((int8_t)imm) == imm) {
    *(--p) = imm;
    emit_reg_reg(0x83, 7, r);
  } else {
    emit_imm32(imm);
    emit_reg_reg(0x81, 7, r);
  }
}

void emit_cmp_reg_reg(uint8_t src, uint8_t dst) {
  emit_modrm(0x3, 0x7 & src, 0x7 & dst);
  *(--p) = 0x3b;
  emit_rex(1, src >> 3, 0, dst >> 3);
}

void emit_jcc32(enum jcc_cond cond, int64_t offset) {
  int64_t off = offset - (int64_t)emit_offset();
  if ((int32_t)((int8_t)off) == off) {
    *(--p) = (int8_t)off;
    *(--p) = cond - 0x10;
  } else {
    // TODO assert that off fits in int32_t
    emit_imm32((int32_t)off);
    *(--p) = cond;
    *(--p) = 0x0f;
  }
}

void emit_jmp32(int32_t offset) {
  emit_imm32(offset);
  *(--p) = 0xe9;
}

void emit_jmp_indirect(int32_t offset) {
  emit_imm32(offset);
  emit_modrm(0x0, 4, RBP);
  *(--p) = 0xff;
}

void emit_jmp_abs(enum registers r) {
  emit_modrm(0x3, 4, 0x7 & r);
  *(--p) = 0xff;
  if (r >> 3) {
    emit_rex(0, 0, 0, r >> 3);
  }
}

void emit_reg_reg(uint8_t opcode, uint8_t src, uint8_t dst) {
  emit_modrm(0x3, 0x7 & src, 0x7 & dst);
  *(--p) = opcode;
  emit_rex(1, src >> 3, 0, dst >> 3);
}

void emit_reg_reg2(uint8_t opcode, uint8_t src, uint8_t dst) {
  emit_modrm(0x3, 0x7 & src, 0x7 & dst);
  *(--p) = opcode;
  *(--p) = 0x0f;
  emit_rex(1, src >> 3, 0, dst >> 3);
}

void emit_mem_reg_sib(uint8_t opcode, int32_t offset, uint8_t scale,
                      uint8_t index, uint8_t base, uint8_t reg) {
  if ((int32_t)((int8_t)offset) == offset) {
    *(--p) = (int8_t)offset;
    emit_sib(scale, index, base);
    emit_modrm(0x1, 0x7 & reg, 0x4);
  } else {
    emit_imm32(offset);
    emit_sib(scale, index, base);
    emit_modrm(0x2, 0x7 & reg, 0x4);
  }
  *(--p) = opcode;
  emit_rex(1, reg >> 3, index >> 3, base >> 3);
}

void emit_mem_reg_sib2(uint8_t opcode, int32_t offset, uint8_t scale,
                       uint8_t index, uint8_t base, uint8_t reg) {
  if ((int32_t)((int8_t)offset) == offset) {
    *(--p) = (int8_t)offset;
    emit_sib(scale, index, base);
    emit_modrm(0x1, 0x7 & reg, 0x4);
  } else {
    emit_imm32(offset);
    emit_sib(scale, index, base);
    emit_modrm(0x2, 0x7 & reg, 0x4);
  }
  *(--p) = opcode;
  *(--p) = 0xf;
  emit_rex(1, reg >> 3, index >> 3, base >> 3);
}

void emit_mem_reg(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2) {
  if (low3bits(r1) == RSP) {
    emit_mem_reg_sib(opcode, offset, 0, RSP, r1, r2);
  } else {
    if (offset == 0 && low3bits(r1) != RBP) {
      emit_modrm(0x0, 0x7 & r2, 0x7 & r1);
    } else if ((int32_t)((int8_t)offset) == offset) {
      *(--p) = (int8_t)offset;
      emit_modrm(0x1, 0x7 & r2, 0x7 & r1);
    } else {
      emit_imm32(offset);
      emit_modrm(0x2, 0x7 & r2, 0x7 & r1);
    }
    *(--p) = opcode;
    emit_rex(1, r2 >> 3, 0, r1 >> 3);
  }
}

void emit_mem_load(int32_t offset, uint8_t base, uint8_t dst) {
  emit_mem_reg(ASM_MOV_MR, offset, base, dst);
}

// TODO(djwatson) merge the '2' byte versions
void emit_mem_reg2(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2) {
  if (low3bits(r1) == RSP) {
    emit_mem_reg_sib2(opcode, offset, 0, RSP, r1, r2);
  } else {
    if ((int32_t)((int8_t)offset) == offset) {
      *(--p) = (int8_t)offset;
      emit_modrm(0x1, 0x7 & r2, 0x7 & r1);
    } else {
      emit_imm32(offset);
      emit_modrm(0x2, 0x7 & r2, 0x7 & r1);
    }
    *(--p) = opcode;
    *(--p) = 0xF;
    emit_rex(1, r2 >> 3, 0, r1 >> 3);
  }
}

/////////////////// opcodes

void emit_op_imm32(uint8_t opcode, uint8_t r1, uint8_t r2, int32_t imm) {
  emit_imm32(imm);
  emit_reg_reg(opcode, r1, r2);
}

void emit_arith_imm(enum ARITH_CODES op, uint8_t src, int32_t imm) {
  if ((int32_t)((int8_t)imm) == imm) {
    *(--p) = imm;
    emit_reg_reg(0x83, op, src);
  } else {
    emit_imm32(imm);
    emit_reg_reg(0x81, op, src);
  }
}

void emit_push(uint8_t r) {
  *(--p) = 0x50 + (0x7 & r);
  if (r >> 3) {
    emit_rex(0, 0, 0, r >> 3);
  }
}

void emit_pop(uint8_t r) {
  // emit_modrm(0x3, 0, 0x7 & r);
  //*(--p) = 0x8f;
  *(--p) = 0x58 | (0x7 & r);
  if (r >> 3) {
    emit_rex(0, 0, 0, r >> 3);
  }
}

void emit_cmovl(uint8_t dst, uint8_t src) {
  emit_modrm(0x3, 0x7 & src, 0x7 & dst);
  *(--p) = 0x4c;
  *(--p) = 0x0f;
  emit_rex(1, src >> 3, 0, dst >> 3);
}

/////////////////// memory

void restore_callee_regs() {
  for (uint8_t i = 0; i < 5; i++) {
    emit_pop(callee_save[i]);
  }
}
void save_callee_regs() {
  for (uint8_t i = 5; i > 0; i--) {
    emit_push(callee_save[i - 1]);
  }
}
