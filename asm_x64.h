// Copyright 2023 Dave Watson

#pragma once


#include <stdint.h>

#include "x64.h"
enum ARITH_CODES {
  OP_ARITH_ADD = 0,
  OP_ARITH_SUB = 5,
  OP_ARITH_CMP = 7,
  OP_ARITH_NONE = 255,
};

enum OPCODES {
  OP_ADD = 0x01,
  OP_SUB = 0x29,
  OP_XCHG = 0x87,
  OP_MOV = 0x89,
  OP_MOV_MR = 0x8b,
  OP_MOV_RM = 0x89,
  OP_MOV8 = 0x88,
  OP_MOV8_MR = 0x8a,
  OP_MOVZX8 = /* 0x0f */ 0xB6,
  OP_NOP = 0x90,
  OP_XOR = 0x90,
  OP_TEST = 0x85,
  OP_TEST_IMM = 0xf7,
  OP_AND_IMM = 0x81,
  OP_CMP_IMM = 0x81,
  OP_CMP = 0x39,
  OP_LEA = 0x8d,
  OP_AND = 0x83,
  OP_SAR_CONST = 0xC1,
  OP_SHL_CONST = 0xC1,
  OP_CQO = 0x99,
  OP_IDIV = 0xF7,
  OP_IMUL = 0xAF,
};

void emit_init();
void emit_cleanup();
int64_t emit_offset();
void emit_advance(int64_t offset);
void emit_bind(uint64_t label, uint64_t jmp);
void emit_check();

void emit_ret();
void emit_jmp32(int32_t offset);
void emit_jmp_abs(enum registers r);
void emit_jmp_indirect(int32_t offset);
void emit_call_indirect(uint8_t r);
void emit_call_indirect_mem(int32_t offset);
void emit_call32(int32_t offset);
void emit_mov64(uint8_t r, int64_t imm);
void emit_pop(uint8_t r);
void emit_push(uint8_t r);
void emit_mem_reg(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2);
void emit_mem_reg2(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2);
void emit_mem_reg_sib(uint8_t opcode, int32_t offset, uint8_t scale,
                      uint8_t index, uint8_t base, uint8_t reg);
void emit_mem_reg_sib2(uint8_t opcode, int32_t offset, uint8_t scale,
                       uint8_t index, uint8_t base, uint8_t reg);
void emit_rex(uint8_t w, uint8_t r, uint8_t x, uint8_t b);
void emit_imm8(uint8_t imm);
void emit_imm32(int32_t imm);
void emit_reg_reg(uint8_t opcode, uint8_t src, uint8_t dst);
void emit_reg_reg2(uint8_t opcode, uint8_t src, uint8_t dst);
void emit_jcc32(enum jcc_cond cond, int64_t offset);
void emit_op_imm32(uint8_t opcode, uint8_t r1, uint8_t r2, int32_t imm);
void emit_cmp_reg_imm32(uint8_t r, int32_t imm);
void emit_cmp_mem32_imm32(int32_t offset, uint8_t r1, int32_t imm);
void emit_arith_imm(enum ARITH_CODES op, uint8_t src, int32_t imm);
