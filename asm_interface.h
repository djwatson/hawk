// Functions implemented in asm_x64.c and asm_aarch64.c that are referenced
// from other translation units. Keep this in sync to track the shared
// backend interface.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct emit_state emit_state;
enum jcc_cond;

void asm_mark_unallocatable(bool used[]);
bool asm_is_callee_saved(uint8_t reg);
void asm_load_constant(emit_state *s, int idx, uint8_t dst);
void asm_patch_constant_pool(emit_state *s);

void restore_callee_regs(emit_state *s);
void save_callee_regs(emit_state *s);

void emit_ret(emit_state *s);
void emit_jmp32(emit_state *s, int64_t target);
void emit_jmp32_patch_here(emit_state *s, int64_t patch);
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
void emit_jcc32(emit_state *s, enum jcc_cond cond, int64_t offset);
void emit_cmp(emit_state *s, uint8_t lhs, uint8_t rhs);
void emit_cmp_constant(emit_state *s, uint8_t reg, int64_t imm);
void emit_test_constant(emit_state *s, uint8_t reg, int64_t imm);
void emit_and_constant(emit_state *s, uint8_t dst, uint8_t src, int64_t imm);
void emit_add(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_add_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm);
void emit_sub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_sub_constant(emit_state *s, uint8_t dst, uint8_t lhs, int64_t imm);
void emit_mov(emit_state *s, uint8_t dst, uint8_t src);
void emit_fadd(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_fsub(emit_state *s, uint8_t dst, uint8_t lhs, uint8_t rhs);
void emit_fadd_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm);
void emit_fsub_constant(emit_state *s, uint8_t dst, uint8_t lhs, double imm);
void emit_fcmp(emit_state *s, uint8_t lhs, uint8_t rhs);
void emit_fcmp_constant(emit_state *s, uint8_t reg, double imm);
void emit_fmov_constant(emit_state *s, uint8_t dst, double imm);
