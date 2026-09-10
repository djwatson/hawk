#include "regalloc.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asm.h"
#include "hawk.h"
#include "ir.h"

// The backwards pass picks spills and records the ends of register lifetimes.
// The forward emitter reloads operands on demand and frees registers at those
// endpoints. Spilled values can have several separate register lifetimes.

struct reg_lifetime_end {
  uint32_t pos;
  uint16_t value_id;
};

static void end_lifetime(regalloc_state *s, uint16_t value_id, uint16_t ir_idx,
                         regalloc_phase phase) {
  arrput(s->ends, ((reg_lifetime_end){3u * ir_idx + phase, value_id}));
}

static bool live_remove(uint16_t *live, uint16_t *count, uint16_t value) {
  for (uint16_t i = 0; i < *count; i++) {
    if (live[i] == value) {
      live[i] = live[--(*count)];
      return true;
    }
  }
  return false;
}

static bool live_add(uint16_t *live, uint16_t *count, uint16_t value) {
  for (uint16_t i = 0; i < *count; i++) {
    if (live[i] == value) {
      return false;
    }
  }
  live[(*count)++] = value;
  return true;
}

static void limit_live_values(regalloc_state *s, uint16_t *live,
                              uint16_t *count, uint16_t max,
                              uint32_t const *use_pos) {
  while (*count > max) {
    uint16_t farthest_i = 0;
    for (uint16_t i = 1; i < *count; i++) {
      if (use_pos[live[i]] > use_pos[live[farthest_i]]) {
        farthest_i = i;
      }
    }
    uint16_t spill_value = live[farthest_i];
    live[farthest_i] = live[--(*count)];
    auto ins = &s->t->ins[spill_value];
    if (ins->spill == SPILL_NONE) {
      if (s->next_spill == SPILL_NONE) {
        abort();
      }
      ins->spill = s->next_spill++;
    }
  }
}

static bool slot_is_zero(trace const *t, slot s) {
  return s.constant && is_fixnum(t->consts[s.loc]) &&
         to_fixnum(t->consts[s.loc]) == 0;
}

static bool ins_clobbers_regs(ir_ins const *ins) {
  return ir_is_vm_call(ins->op) || ins->op == IR_CCALL ||
         ins->op == IR_CALLCC || ins->op == IR_CALLCC_RESUME ||
         (ins->op == IR_MOD && ins->type == FLONUM_TAG);
}

static bool needs_output_reg(regalloc_state const *s, uint16_t ir_idx) {
  auto op = s->t->ins[ir_idx].op;
  return op != IR_PMOV && op != IR_REF && op != IR_CARG && s->last_use[ir_idx];
}

static uint8_t regalloc_collect_carg_args(trace const *t, slot chain,
                                          slot *args) {
  if (slot_is_zero(t, chain)) {
    return 0;
  }
  assert(!chain.constant);
  auto carg = &t->ins[chain.loc];
  assert(carg->op == IR_CARG);
  uint8_t count = 0;
  if (!carg->op1.constant) {
    args[count++] = carg->op1;
  }
  return (uint8_t)(count +
                   regalloc_collect_carg_args(t, carg->op2, args + count));
}

uint8_t regalloc_collect_ir_args(trace const *t, ir_ins const *ins,
                                 slot *args) {
  uint8_t count = 0;
  slot op1 = ins->op1;
  slot op2 = ins->op2;
  if (ins->op == IR_STORE || ins->op == IR_STORE_CHAR ||
      ins->op == IR_STORE_BYTE || ins->op == IR_FLVECTOR_SET) {
    auto ptr_ins = &t->ins[op1.loc];
    count = regalloc_collect_ir_args(t, ptr_ins, args);
    if (!op2.constant) {
      args[count++] = op2;
    }
    return count;
  }
  if (ins->op == IR_CARG) {
    return 0;
  }
  if (ins->op == IR_STACK_LEN_EQ || ins->op == IR_STACK_FITS_RESET ||
      ins->op == IR_STACK_SET_TOP) {
    return 0;
  }
  if (ins->op == IR_CALLCC) {
    if (!op1.constant) {
      args[count++] = op1;
    }
    return (uint8_t)(count +
                     regalloc_collect_carg_args(t, op2, args + count));
  }
  if (ins->op == IR_CCALL) {
    return regalloc_collect_carg_args(t, op2, args);
  }
  switch (ir_ins_types[ins->op]) {
  case IR_ARG_IR_IR:
    if (!op1.constant) {
      args[count++] = op1;
    }
    if (!op2.constant) {
      args[count++] = op2;
    }
    break;
  case IR_ARG_IR_NONE:
  case IR_ARG_IR_ADDR:
    if (!op1.constant) {
      args[count++] = op1;
    }
    break;
  default:
    break;
  }
  return count;
}

static bool value_used_by_args(slot const *args, uint8_t arg_count,
                                uint16_t value_id) {
  for (uint8_t arg = 0; arg < arg_count; arg++) {
    if (args[arg].loc == value_id) {
      return true;
    }
  }
  return false;
}

static int compare_lifetime_ends(void const *a, void const *b) {
  auto lhs = (reg_lifetime_end const *)a;
  auto rhs = (reg_lifetime_end const *)b;
  return (lhs->pos < rhs->pos) - (lhs->pos > rhs->pos);
}

static void collect_lifetimes(regalloc_state *s) {
  size_t ins_len = arrlen(s->t->ins);
  if (ins_len == 0) {
    return;
  }
  s->last_use = calloc(ins_len, sizeof(*s->last_use));
  if (!s->last_use) {
    abort();
  }

  size_t snap_len = arrlen(s->t->snaps);
  size_t cur_snap = snap_len;
  uint16_t cur_snap_end_ir = ins_len;

  uint16_t gpr_live[ins_len];
  uint16_t fpr_live[ins_len];
  uint16_t gpr_live_count = 0;
  uint16_t fpr_live_count = 0;
  uint32_t *use_pos = malloc(sizeof(uint32_t) * ins_len);
  if (!use_pos) {
    abort();
  }
  for (size_t i = 0; i < ins_len; i++) {
    use_pos[i] = UINT32_MAX;
  }
  for (size_t i = ins_len; i > 0; i--) {
    uint16_t value_id = (uint16_t)(i - 1);
    auto ins = &s->t->ins[value_id];
    slot args[UINT8_MAX];
    uint8_t arg_count = regalloc_collect_ir_args(s->t, ins, args);
    while (cur_snap != 0 &&
           (cur_snap == snap_len || s->t->snaps[cur_snap].ir >= (i - 1))) {
      cur_snap--;
      auto cur = &s->t->snaps[cur_snap];
      auto entries = snap_entries_const(s->t, cur);
      for (size_t slot_i = 0; slot_i < snap_nent(cur); slot_i++) {
        auto val = entries[slot_i].val;
        // Snapshots extend liveness only beyond the final ordinary use.
        if (!val.constant && !s->last_use[val.loc]) {
          // A use at the snapshot boundary must survive operand loading.
          regalloc_phase phase = cur_snap_end_ir == value_id &&
                                         value_used_by_args(args, arg_count, val.loc)
                                     ? REGALLOC_INPUTS
                                     : REGALLOC_BEFORE;
          s->last_use[val.loc] = 3u * cur_snap_end_ir + phase;
          end_lifetime(s, val.loc, cur_snap_end_ir, phase);
          bool flonum = s->t->ins[val.loc].type == FLONUM_TAG;
          auto live = flonum ? fpr_live : gpr_live;
          auto live_count = flonum ? &fpr_live_count : &gpr_live_count;
          live_add(live, live_count, val.loc);
          if (use_pos[val.loc] == UINT32_MAX) {
            use_pos[val.loc] = cur_snap_end_ir;
          }
          limit_live_values(s, live, live_count,
                            flonum ? FPR_ALLOCATABLE : GPR_ALLOCATABLE,
                            use_pos);
        }
      }
      cur_snap_end_ir = cur->ir;
    }

    bool was_live = ins->type == FLONUM_TAG
                        ? live_remove(fpr_live, &fpr_live_count, value_id)
                        : live_remove(gpr_live, &gpr_live_count, value_id);
    if (!was_live && s->last_use[value_id]) {
      end_lifetime(s, value_id, value_id, REGALLOC_OUTPUT);
    }
    if (ins_clobbers_regs(ins)) {
      limit_live_values(s, gpr_live, &gpr_live_count, 0, use_pos);
      limit_live_values(s, fpr_live, &fpr_live_count, 0, use_pos);
    }

    for (uint8_t arg = 0; arg < arg_count; arg++) {
      uint16_t loc = args[arg].loc;
      if (!s->last_use[loc]) {
        s->last_use[loc] = 3u * value_id + REGALLOC_INPUTS;
      }
      bool flonum = s->t->ins[loc].type == FLONUM_TAG;
      auto live = flonum ? fpr_live : gpr_live;
      auto live_count = flonum ? &fpr_live_count : &gpr_live_count;
      if (live_add(live, live_count, loc)) {
        end_lifetime(s, loc, value_id, REGALLOC_INPUTS);
      }
      use_pos[loc] = value_id;
    }
    // Conservatively reserve output space alongside inputs; emission can
    // reuse registers of inputs whose last use is this instruction.
    uint16_t gpr_limit = GPR_ALLOCATABLE;
    uint16_t fpr_limit = FPR_ALLOCATABLE;
    if (needs_output_reg(s, value_id)) {
      if (ins->type == FLONUM_TAG) {
        fpr_limit--;
      } else {
        gpr_limit--;
      }
    }
    limit_live_values(s, gpr_live, &gpr_live_count, gpr_limit, use_pos);
    limit_live_values(s, fpr_live, &fpr_live_count, fpr_limit, use_pos);
  }
  free(use_pos);
  if (arrlen(s->ends)) {
    qsort(s->ends, arrlen(s->ends), sizeof(*s->ends), compare_lifetime_ends);
  }
}

uint8_t regalloc_find_current_reg_for_value(regalloc_state *s,
                                            uint16_t value_id) {
  for (uint16_t reg = 0; reg < MAX_REG; reg++) {
    if (s->regs[reg] == ALLOC_NONE || s->regs[reg] == ALLOC_UNALLOCATABLE) {
      continue;
    }
    if (s->regs[reg] == value_id) {
      return (uint8_t)reg;
    }
  }
  return REG_NONE;
}

uint8_t regalloc_find_free_reg(regalloc_state *s, bool flonum,
                               ir_ins const *cur_ins) {
  slot args[UINT8_MAX];
  uint8_t arg_count = cur_ins ? regalloc_collect_ir_args(s->t, cur_ins, args) : 0;
  uint16_t start = flonum ? FPR_REG_START : 0;
  uint16_t end = flonum ? FPR_REG_END : FPR_REG_START;
  uint16_t spill_reg = UINT16_MAX;
  uint32_t farthest_last_use = 0;
  for (uint16_t i = start; i < end; i++) {
    if (s->regs[i] == ALLOC_UNALLOCATABLE) {
      continue;
    }
    if (s->regs[i] == ALLOC_NONE) {
      return (uint8_t)i;
    }

    uint16_t value_id = s->regs[i];
    if (value_used_by_args(args, arg_count, value_id)) {
      continue;
    }
    if (s->t->ins[value_id].spill == SPILL_NONE) {
      continue;
    }
    // Planned lifetime ends normally provide space. If emission needs more,
    // prefer a backed value with a distant final use over register order.
    uint32_t candidate_last_use = s->last_use[value_id];

    if (spill_reg == UINT16_MAX || candidate_last_use > farthest_last_use) {
      farthest_last_use = candidate_last_use;
      spill_reg = (uint8_t)i;
    }
  }
  if (spill_reg == UINT16_MAX) {
    abort();
  }

  s->regs[spill_reg] = ALLOC_NONE;
  return (uint8_t)spill_reg;
}

void regalloc_free_regs(regalloc_state *s, uint16_t cur_idx,
                        regalloc_phase phase) {
  uint32_t pos = 3u * cur_idx + phase;
  while (arrlen(s->ends) && arrlast(s->ends)->pos <= pos) {
    uint8_t reg =
        regalloc_find_current_reg_for_value(s, arrlast(s->ends)->value_id);
    arrpop(s->ends);
    if (reg != REG_NONE) {
      s->regs[reg] = ALLOC_NONE;
    }
  }
}

uint8_t regalloc_ensure_arg_reg(regalloc_state *s, uint16_t cur_idx,
                                ir_ins const *ins, uint16_t value_id) {
  (void)cur_idx;
  auto in = &s->t->ins[value_id];
  uint8_t reg = regalloc_find_current_reg_for_value(s, value_id);
  if (reg == REG_NONE) {
    assert(in->spill != SPILL_NONE);
    reg = regalloc_find_free_reg(s, in->type == FLONUM_TAG, ins);
    s->regs[reg] = value_id;

    LOG(regalloc, "ASSIGN arg reg=%u value=%u from_spill=%u ir_idx=%u", reg, value_id,
        in->spill, cur_idx);
  }
  return reg;
}

void regalloc_assign_output(regalloc_state *s, uint16_t ir_idx, ir_ins *ins) {
  if (ins->op == IR_PMOV) {
    if (ins->reg != REG_NONE && s->last_use[ir_idx]) {
      s->regs[ins->prev_reg] = ir_idx;
    }
    return;
  }
  if (!needs_output_reg(s, ir_idx)) {
    return;
  }
  if (ins->reg == REG_NONE) {
    ins->reg = regalloc_find_free_reg(s, ins->type == FLONUM_TAG, ins);
  }
  s->regs[ins->reg] = ir_idx;
}

void regalloc_state_init(regalloc_state *s, trace *t) {
  memset(s, 0, sizeof(*s));
  s->t = t;
  s->next_spill = 0;
  arr_for_each_idx(t->ins, i) {
    if (t->ins[i].spill != SPILL_NONE && t->ins[i].spill >= s->next_spill) {
      s->next_spill = (uint16_t)(t->ins[i].spill + 1);
    }
  }
  memset(s->regs, 0xff, sizeof(s->regs));
  bool unallocatable_regs[MAX_REG] = {0};
  asm_init_unallocatable_regs(unallocatable_regs);
  for (uint16_t reg = 0; reg < MAX_REG; reg++) {
    if (unallocatable_regs[reg]) {
      s->regs[reg] = ALLOC_UNALLOCATABLE;
    }
  }
  collect_lifetimes(s);
}

void regalloc_state_free(regalloc_state *s) {
  arrfree(s->ends);
  free(s->last_use);
  memset(s, 0, sizeof(*s));
}
