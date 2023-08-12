#define _DEFAULT_SOURCE

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "emit_x64.h"

static uint8_t *mtop = NULL;
static uint8_t *mend = NULL;
static uint8_t *p = NULL;

static const size_t page_cnt = 1000;
static const size_t msize = page_cnt * 4096;

#define auto __auto_type

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

void emit_imm8(uint8_t imm) {
  *(--p) = imm;
}

void emit_imm64(int64_t imm) {
  p -= sizeof(int64_t);
  *(int64_t *)p = imm;
}

void emit_imm32(int32_t imm) {
  p -= sizeof(int32_t);
  *(int32_t *)p = imm;
}

void emit_mov64(uint8_t r, int64_t imm) {
  if ((int64_t)((int32_t)imm) != imm) {
    emit_imm64(imm);
    *(--p) = 0xb8 | (0x7 & r);
    emit_rex(1, 0, 0, r >> 3);
  } else {
    emit_imm32((int32_t)imm);
    *(--p) = 0xb8 | (0x7 & r);
    emit_rex(0, 0, 0, r >> 3);
  }
}

void emit_call_indirect(uint8_t r) {
  emit_modrm(0x3, 0x2, 0x7 & r);
  *(--p) = 0xff;
  emit_rex(1, 0, 0, r >> 3);
}

// TODO offset
void emit_call32(int32_t offset) {
  emit_imm32(offset);
  *(--p) = 0xe8;
}

void emit_ret() { *(--p) = 0xc3; }

void emit_cmp_reg_imm32(uint8_t r, int32_t imm) {
  if ((int32_t)((int8_t)imm) != imm) {
    emit_imm32(imm);
    emit_reg_reg(0x81, 7, r);
  } else {
    *(--p) = imm;
    emit_reg_reg(0x83, 7, r);
  }
}

void emit_cmp_reg_reg(uint8_t src, uint8_t dst) {
  emit_modrm(0x3, 0x7 & src, 0x7 & dst);
  *(--p) = 0x3b;
  emit_rex(1, src >> 3, 0, dst >> 3);
}

// TODO: could test for short offset
void emit_jcc32(enum jcc_cond cond, int32_t offset) {
  if ((int32_t)((int8_t)offset) == offset) {
    *(--p) = (int8_t)offset;
    *(--p) = cond - 0x10;
  } else {
    emit_imm32(offset);
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

void emit_mem_reg(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2) {
  if ((0x7 & r1) == RSP) {
    emit_mem_reg_sib(opcode, offset, 0, RSP, r1, r2);
  } else {
    if ((int32_t)((int8_t)offset) == offset) {
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

/////////////////// opcodes

void emit_op_imm32(uint8_t opcode, uint8_t r1, uint8_t r2, int32_t imm) {
  emit_imm32(imm);
  emit_reg_reg(opcode, r1, r2);
}

void emit_arith_imm(enum ARITH_CODES op, uint8_t src, int32_t imm) {
  if ((int32_t)((int8_t)imm) != imm) {
    emit_imm32(imm);
    emit_reg_reg(0x81, op, src);
  } else {
    *(--p) = imm;
    emit_reg_reg(0x83, op, src);
  }
}

void emit_push(uint8_t r) {
  *(--p) = 0x50 + (0x7 & r);
  if (r >> 3) {
    emit_rex(0, 0, 0, r >> 3);
  }
}

void emit_pop(uint8_t r) {
  emit_modrm(0x3, 0, 0x7 & r);
  *(--p) = 0x8f;
  emit_rex(1, 0, 0, r >> 3);
}

void emit_cmovl(uint8_t dst, uint8_t src) {
  emit_modrm(0x3, 0x7 & src, 0x7 & dst);
  *(--p) = 0x4c;
  *(--p) = 0x0f;
  emit_rex(1, src >> 3, 0, dst >> 3);
}

/////////////////// memory

uint64_t emit_offset() { return (uint64_t)p; }

void emit_bind(uint64_t label, uint64_t jmp) {
  assert(jmp);
  assert(label);
  auto offset = (int32_t)((int64_t)label - (int64_t)jmp);
  *(int32_t *)(jmp - 4) = offset;
}
void emit_advance(int64_t offset) { p -= offset; }

void emit_check() {
  if (p - mtop <= 64) {
    printf("Fail: Out of jit memory\n");
    exit(-1);
  }
}

void emit_init() {
  if (mtop) {
    return;
  }

  mtop = (uint8_t *)mmap(NULL, msize, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(mtop);
  p = mtop + msize;
  mend = p;
}

void emit_cleanup() { munmap(mtop, msize); }

/*
int main() {
  emit_init();
  auto end = emit_offset();
  emit_check();

  emit_ret();
  //emit_mov64(RAX, 101);

  //emit_imm32(101);
  // *(--p) = 0xb8 | RAX;

  long foo = 101;
  emit_imm64((int64_t)&foo);
  *(--p) = 0xa1;
  emit_rex(1, 0, 0, 0);

  //disassemble(emit_offset(), end - emit_offset());

  long (*res)(void) = emit_offset();

  long result = res();
  printf("Res: %li\n", result);

  emit_cleanup();

  return 0;
}
*/
