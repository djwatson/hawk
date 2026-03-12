#pragma once

#include "ir.h"

typedef struct {
  uint16_t ir_idx;
  bool before;
  bool is_snap;
  uint32_t next;
} next_use;

typedef struct regalloc_state {
  trace *t;
  uint32_t *uses;
  next_use *next_uses;
  uint16_t regs[MAX_REG];
  uint8_t next_spill;
} regalloc_state;

void regalloc_state_init(regalloc_state *s, trace *t);
void regalloc_state_free(regalloc_state *s);
void regalloc_collect_next_uses(regalloc_state *s);
uint8_t regalloc_collect_ir_args(trace const *t, ir_ins const *ins, slot *args);
uint8_t regalloc_find_current_reg_for_value(regalloc_state *s,
                                            uint16_t value_id);
uint8_t regalloc_find_free_reg(regalloc_state *s, bool flonum,
                               ir_ins const *cur_ins);
void regalloc_maybe_free_reg(regalloc_state *s, uint16_t cur_idx, uint16_t idx,
                             bool keep_current_before);
void regalloc_maybe_free_snapshot(regalloc_state *s, uint16_t cur_idx,
                                  snap const *sn);
uint8_t regalloc_materialize_arg_or_ensure_loc(regalloc_state *s,
                                               uint16_t cur_idx,
                                               ir_ins const *ins,
                                               uint16_t value_id);
void regalloc_assign_output(regalloc_state *s, uint16_t ir_idx, ir_ins *ins);
