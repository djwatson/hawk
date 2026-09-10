#pragma once

#include "ir.h"

enum : uint16_t {
  ALLOC_NONE = UINT16_MAX,
  ALLOC_UNALLOCATABLE = UINT16_MAX - 1,
};

typedef enum {
  REGALLOC_BEFORE,
  REGALLOC_INPUTS,
  REGALLOC_OUTPUT,
} regalloc_phase;

typedef struct reg_lifetime_end reg_lifetime_end;

typedef struct regalloc_state {
  trace *t;
  uint32_t *last_use;
  reg_lifetime_end *ends;
  uint16_t regs[MAX_REG];
  uint16_t next_spill;
} regalloc_state;

void regalloc_state_init(regalloc_state *s, trace *t);
void regalloc_state_free(regalloc_state *s);
uint8_t regalloc_collect_ir_args(trace const *t, ir_ins const *ins, slot *args);
uint8_t regalloc_find_current_reg_for_value(regalloc_state *s,
                                            uint16_t value_id);
uint8_t regalloc_find_free_reg(regalloc_state *s, bool flonum,
                               ir_ins const *cur_ins);
void regalloc_free_regs(regalloc_state *s, uint16_t cur_idx,
                        regalloc_phase phase);
uint8_t regalloc_ensure_arg_reg(regalloc_state *s, uint16_t cur_idx,
                                ir_ins const *ins, uint16_t value_id);
void regalloc_assign_output(regalloc_state *s, uint16_t ir_idx, ir_ins *ins);
