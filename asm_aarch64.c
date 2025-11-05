// Temporary AArch64 stubs to make the build succeed.

#include <stdint.h>

#include "asm_aarch64.h"

static int64_t fake_offset;

static void bump(int64_t delta) {
  fake_offset += delta;
}

void emit_init() {
  fake_offset = 0;
}

void emit_cleanup() {}

int64_t emit_offset() {
  return fake_offset;
}

void emit_advance(int64_t offset) {
  fake_offset += offset;
}

void emit_bind(uint64_t label, uint64_t jmp) {
  (void)label;
  (void)jmp;
}

void emit_check() {}

void restore_callee_regs() {}

void save_callee_regs() {}

void emit_ret() {
  bump(1);
}

void emit_jmp32(int32_t offset) {
  (void)offset;
  bump(4);
}

void emit_jmp_abs(enum registers r) {
  (void)r;
  bump(4);
}

void emit_jmp_indirect(int32_t offset) {
  (void)offset;
  bump(4);
}

void emit_call_indirect(uint8_t r) {
  (void)r;
  bump(4);
}

void emit_call_indirect_mem(int32_t offset) {
  (void)offset;
  bump(4);
}

void emit_call32(int32_t offset) {
  (void)offset;
  bump(4);
}

void emit_mov64(uint8_t r, int64_t imm) {
  (void)r;
  (void)imm;
  bump(8);
}

void emit_pop(uint8_t r) {
  (void)r;
  bump(1);
}

void emit_push(uint8_t r) {
  (void)r;
  bump(1);
}

void emit_mem_reg(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2) {
  (void)opcode;
  (void)offset;
  (void)r1;
  (void)r2;
  bump(4);
}

void emit_mem_reg2(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2) {
  (void)opcode;
  (void)offset;
  (void)r1;
  (void)r2;
  bump(4);
}

void emit_mem_reg_sib(uint8_t opcode, int32_t offset, uint8_t scale,
                      uint8_t index, uint8_t base, uint8_t reg) {
  (void)opcode;
  (void)offset;
  (void)scale;
  (void)index;
  (void)base;
  (void)reg;
  bump(4);
}

void emit_mem_reg_sib2(uint8_t opcode, int32_t offset, uint8_t scale,
                       uint8_t index, uint8_t base, uint8_t reg) {
  (void)opcode;
  (void)offset;
  (void)scale;
  (void)index;
  (void)base;
  (void)reg;
  bump(4);
}

void emit_rex(uint8_t w, uint8_t r, uint8_t x, uint8_t b) {
  (void)w;
  (void)r;
  (void)x;
  (void)b;
  bump(1);
}

void emit_imm8(uint8_t imm) {
  (void)imm;
  bump(1);
}

void emit_imm32(int32_t imm) {
  (void)imm;
  bump(4);
}

void emit_reg_reg(uint8_t opcode, uint8_t src, uint8_t dst) {
  (void)opcode;
  (void)src;
  (void)dst;
  bump(2);
}

void emit_reg_reg2(uint8_t opcode, uint8_t src, uint8_t dst) {
  (void)opcode;
  (void)src;
  (void)dst;
  bump(2);
}

void emit_jcc32(enum jcc_cond cond, int64_t offset) {
  (void)cond;
  (void)offset;
  bump(4);
}

void emit_op_imm32(uint8_t opcode, uint8_t r1, uint8_t r2, int32_t imm) {
  (void)opcode;
  (void)r1;
  (void)r2;
  (void)imm;
  bump(4);
}

void emit_cmp_reg_imm32(uint8_t r, int32_t imm) {
  (void)r;
  (void)imm;
  bump(4);
}

void emit_cmp_mem32_imm32(int32_t offset, uint8_t r1, int32_t imm) {
  (void)offset;
  (void)r1;
  (void)imm;
  bump(4);
}

void emit_arith_imm(enum ARITH_CODES op, uint8_t src, int32_t imm) {
  (void)op;
  (void)src;
  (void)imm;
  bump(4);
}
