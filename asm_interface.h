// Functions implemented in asm_x64.c and asm_aarch64.c that are referenced
// from other translation units. Keep this in sync to track the shared
// backend interface.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct emit_state emit_state;
enum jcc_cond;
enum label_patch_kind;
typedef struct label_patch label_patch;
typedef struct label label;

bool asm_is_callee_saved(uint8_t reg);
void asm_load_constant(emit_state *s, int idx, uint8_t dst);
void asm_patch_constant_pool(emit_state *s);
void asm_patch_jmp32(emit_state *s, uint8_t *loc, uint8_t const *target);
void asm_patch_jcc32(emit_state *s, uint8_t *loc, uint8_t const *target);
void asm_emit_jmp32_resolved(emit_state *s, uint8_t const *target);
uint8_t *asm_emit_jmp32_placeholder(emit_state *s);
void asm_emit_jcc32_resolved(emit_state *s, enum jcc_cond cond,
                             uint8_t const *target);
uint8_t *asm_emit_jcc32_placeholder(emit_state *s, enum jcc_cond cond);
void asm_write_jmp32_at(emit_state *s, uint8_t *loc, uint8_t const *target);

void restore_callee_regs(emit_state *s);
void save_callee_regs(emit_state *s);

void emit_ret(emit_state *s);
void emit_label(emit_state *s, label *label);
void emit_jmp32(emit_state *s, label *target);
void emit_mov64(emit_state *s, uint8_t r, int64_t imm);
void emit_call_reg(emit_state *s, uint8_t r);
void emit_call32(emit_state *s, int64_t target);
void emit_push(emit_state *s, uint8_t r);
void emit_pop(emit_state *s, uint8_t r);
void emit_fmov(emit_state *s, uint8_t dst, uint8_t src);
void emit_push_regs(emit_state *s, uint8_t const *regs, size_t count,
                    bool abi);
void emit_pop_regs(emit_state *s, uint8_t const *regs, size_t count, bool abi);
void emit_mem_load(emit_state *s, int32_t offset, uint8_t base, uint8_t dst);
void emit_fmem_load(emit_state *s, int32_t offset, uint8_t base, uint8_t dst);
void emit_store(emit_state *s, int32_t offset, uint8_t base, uint8_t src);
void emit_fstore(emit_state *s, int32_t offset, uint8_t base, uint8_t src);
void emit_store_constant(emit_state *s, int32_t offset, uint8_t base,
                         int64_t value);
void emit_jcc32(emit_state *s, enum jcc_cond cond, label *target);
void emit_cmp(emit_state *s, uint8_t lhs, uint8_t rhs);
void emit_cmp_constant(emit_state *s, uint8_t reg, int64_t imm);
void emit_test_constant(emit_state *s, uint8_t reg, int64_t imm);
void emit_and_constant(emit_state *s, uint8_t dst, uint8_t src, int64_t imm);
void emit_add(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_add_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm);
void emit_sub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_mul(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_mul_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm);
void asm_emit_fixnum_add_guard_overflow(emit_state *s, uint8_t dst,
                                        uint8_t lhs, uint8_t rhs,
                                        label *overflow_target);
void asm_emit_fixnum_add_constant_guard_overflow(emit_state *s, uint8_t dst,
                                                 uint8_t lhs, int64_t imm,
                                                 label *overflow_target);
void asm_emit_fixnum_sub_guard_overflow(emit_state *s, uint8_t dst,
                                        uint8_t lhs, uint8_t rhs,
                                        label *overflow_target);
void asm_emit_fixnum_sub_constant_guard_overflow(emit_state *s, uint8_t dst,
                                                 uint8_t lhs, int64_t imm,
                                                 label *overflow_target);
void asm_emit_fixnum_mul_guard_overflow(emit_state *s, uint8_t dst,
                                        uint8_t lhs, uint8_t rhs,
                                        label *overflow_target);
void asm_emit_fixnum_mul_constant_guard_overflow(emit_state *s, uint8_t dst,
                                                 uint8_t lhs, int64_t imm,
                                                 label *overflow_target);
void emit_sar_constant(emit_state *s, uint8_t dst, uint8_t src, uint8_t imm);
void emit_quotient(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_quotient_constant(emit_state *s, uint8_t dst, uint8_t lhs,
                            int64_t imm);
void emit_mod(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_mod_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm);
void emit_sub_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm);
void emit_mov(emit_state *s, uint8_t dst, uint8_t src);
void emit_fadd(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_fsub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_fmul(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_fdiv(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_ftruncate(emit_state *s, uint8_t dst, uint8_t src);
void emit_fadd_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm);
void emit_fsub_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm);
void emit_fcmp(emit_state *s, uint8_t lhs, uint8_t rhs);
void emit_fcmp_constant(emit_state *s, uint8_t reg, double imm);
void emit_fmov_constant(emit_state *s, uint8_t dst, double imm);
void emit_double_to_int64_trunc(emit_state *s, uint8_t dst, uint8_t src);
void emit_int64_to_double(emit_state *s, uint8_t dst, uint8_t src);
