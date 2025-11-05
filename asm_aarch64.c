// Temporary AArch64 stubs to make the build succeed.

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "asm_aarch64.h"

extern uint8_t *p;

static void bump(int64_t delta) { p -= delta; }

// Build a single-instruction MOV opcode for small immediates.
static uint32_t mov_imm16_opcode(uint8_t reg, int32_t imm) {
  assert(reg < 31);
  if (imm >= 0 && imm <= 0xFFFF) {
    return 0xD2800000u | ((uint32_t)imm << 5) | reg;
  }
  if (imm >= -0x10000 && imm < 0) {
    uint32_t imm16 = (uint32_t)(~imm) & 0xFFFFu;
    return 0x92800000u | (imm16 << 5) | reg;
  }
  // assert(0 && "immediate out of range for single mov");
  return 0;
}

void restore_callee_regs() { printf("TODO resotre callee save \n"); }

void save_callee_regs() { printf("TODO save callee save \n"); }

static void emit_op(uint32_t code) {
  p -= 4;
  memcpy(p, &code, 4);
}
void emit_ret() { emit_op(0xD65F03C0); }

void emit_jmp32(int32_t offset) { printf("TODO jmp32 \n"); }
void emit_mov64(uint8_t r, int64_t imm) {
  auto code = mov_imm16_opcode(r, imm);
  if (code) {
    emit_op(code);
  } else {
    printf("TODO Immediate too big: 0x%lx\n", imm);
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
