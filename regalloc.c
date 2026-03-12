#include "regalloc.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asm.h"
#include "hawk.h"
#include "ir.h"
#include "lru.h"

typedef struct {
  uint16_t ir_idx;
  bool before;
  bool is_snap;
  uint32_t next;
} next_use;

typedef struct regalloc_state regalloc_state;

static void collect_next_uses(regalloc_state *s);

#define ALLOC_NONE UINT16_MAX
#define ALLOC_UNALLOCATABLE (UINT16_MAX - 1)

typedef struct regalloc_state {
  trace *t;
  uint32_t *uses;
  next_use *next_uses;
  bool *spilled;

  uint16_t regs[MAX_REG];

  dense_loc_entry *dense_locs;
  uint16_t *ir_id_to_dense_map;
  reload_op *ops;
  uint8_t next_spill;
} regalloc_state;

static bool value_is_flonum(trace const *t, uint16_t value_id) {
  return t->ins[value_id].type == FLONUM_TAG;
}

static lru *value_lru_for(lru *gpr, lru *fpr, bool flonum) {
  return flonum ? fpr : gpr;
}

static void limit_live_values(regalloc_state *s, lru *lru, uint16_t max) {
  while (lru->count > max) {
    uint16_t spill_value = lru_pop_oldest(lru);
    s->spilled[spill_value] = true;
  }
}

static uint8_t collect_ir_args(trace const *t, ir_ins const *ins, slot *args) {
  uint8_t count = 0;
  slot op1 = ins->op1;
  slot op2 = ins->op2;
  if (ins->op == IR_STORE) {
    auto ptr_ins = &t->ins[op1.loc];
    count = collect_ir_args(t, ptr_ins, args);
    if (!op2.constant) {
      args[count++] = op2;
    }
    return count;
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

static void add_next_use(regalloc_state *s, uint16_t loc, uint16_t ir_idx,
                         bool before, bool is_snap) {
  auto next = (next_use){.ir_idx = ir_idx,
                         .before = before,
                         .is_snap = is_snap,
                         .next = s->uses[loc]};
  s->uses[loc] = (uint32_t)arrlen(s->next_uses);
  arrput(s->next_uses, next);
}

static void collect_next_uses(regalloc_state *s) {
  size_t ins_len = arrlen(s->t->ins);
  if (ins_len == 0) {
    return;
  }

  s->uses = calloc(ins_len, sizeof(uint32_t));
  if (!s->uses) {
    abort();
  }

  // Use 0 as the null index in use chains.
  arrput(s->next_uses, ((next_use){0}));

  size_t snap_len = arrlen(s->t->snaps);
  size_t cur_snap = snap_len;
  uint16_t cur_snap_end_ir = ins_len;

  s->spilled = calloc(ins_len, sizeof(bool));
  if (!s->spilled) {
    abort();
  }

  lru gpr_live;
  lru fpr_live;
  lru_init(&gpr_live);
  lru_init(&fpr_live);
  for (size_t i = ins_len; i > 0; i--) {
    uint16_t value_id = (uint16_t)(i - 1);
    while (cur_snap != 0 &&
           (cur_snap == snap_len || s->t->snaps[cur_snap].ir >= (i - 1))) {
      cur_snap--;
      auto cur = &s->t->snaps[cur_snap];
      arr_for_each_idx(cur->slots, slot_i) {
        auto val = cur->slots[slot_i].val;
        // We ONLY add snapshots as a 'use' if it doesn't already exist:
        // This is so snapshots don't affect 'find next use' spilling heuristic.
        if (!val.constant && !s->uses[val.loc]) {
          add_next_use(s, val.loc, cur_snap_end_ir, false, true);
          auto value_lru = value_lru_for(&gpr_live, &fpr_live,
                                         value_is_flonum(s->t, val.loc));
          lru_add(value_lru, val.loc);
        }
      }
      limit_live_values(s, &gpr_live, GPR_ALLOCATABLE);
      limit_live_values(s, &fpr_live, FPR_ALLOCATABLE);
      cur_snap_end_ir = cur->ir;
    }

    auto value_lru =
        value_lru_for(&gpr_live, &fpr_live, value_is_flonum(s->t, value_id));
    lru_remove(value_lru, value_id);

    auto ins = &s->t->ins[value_id];
    slot args[3];
    uint8_t arg_count = collect_ir_args(s->t, ins, args);
    for (uint8_t arg = 0; arg < arg_count; arg++) {
      add_next_use(s, args[arg].loc, value_id, true, false);
      auto arg_lru = value_lru_for(&gpr_live, &fpr_live,
                                   value_is_flonum(s->t, args[arg].loc));
      lru_poke(arg_lru, args[arg].loc);
    }
    // TODO if we need tmp values, add them here?
    // In the current regalloc, the output register is live
    // at the same time as the input registers.
    uint16_t gpr_limit = GPR_ALLOCATABLE;
    uint16_t fpr_limit = FPR_ALLOCATABLE;
    if (value_is_flonum(s->t, value_id)) {
      fpr_limit--;
    } else {
      gpr_limit--;
    }
    if (ins->op == IR_RET) {
      gpr_limit--;
    }
    limit_live_values(s, &gpr_live, gpr_limit);
    limit_live_values(s, &fpr_live, fpr_limit);
  }
}

static uint8_t find_current_reg_for_value(regalloc_state *s,
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

static bool value_used_by_ir_ins(trace const *t, ir_ins const *ins,
                                 uint16_t value_id) {
  slot args[3];
  uint8_t arg_count = collect_ir_args(t, ins, args);
  for (uint8_t arg = 0; arg < arg_count; arg++) {
    if (args[arg].loc == value_id) {
      return true;
    }
  }
  return false;
}

static uint8_t find_reg_to_spill(regalloc_state *s, uint16_t start,
                                 uint16_t end, ir_ins const *cur_ins) {
  // Reuse the register whose resident value is already assigned a spill slot
  // and has the farthest immediate next use in this register class.
  uint8_t spill_reg = REG_NONE;
  uint32_t farthest_use = 0;
  bool have_candidate = false;
  for (uint16_t i = start; i < end; i++) {
    if (s->regs[i] == ALLOC_NONE || s->regs[i] == ALLOC_UNALLOCATABLE) {
      continue;
    }

    uint16_t value_id = s->regs[i];
    if (cur_ins && value_used_by_ir_ins(s->t, cur_ins, value_id)) {
      continue;
    }
    if (s->t->ins[value_id].spill == SPILL_NONE) {
      continue;
    }
    uint32_t next_idx = s->uses[value_id];
    uint32_t candidate_next_use =
        next_idx ? s->next_uses[next_idx].ir_idx : UINT32_MAX;

    if (!have_candidate || candidate_next_use > farthest_use) {
      farthest_use = candidate_next_use;
      spill_reg = (uint8_t)i;
      have_candidate = true;
    }
  }
  if (!have_candidate) {
    abort();
  }

  s->regs[spill_reg] = ALLOC_NONE;
  return spill_reg;
}

static uint8_t find_free_reg(regalloc_state *s, bool flonum,
                             ir_ins const *cur_ins) {
  uint16_t start = flonum ? FPR_REG_START : 0;
  uint16_t end = flonum ? FPR_REG_END : FPR_REG_START;
  for (uint16_t i = start; i < end; i++) {
    if (s->regs[i] == ALLOC_UNALLOCATABLE) {
      continue;
    }
    if (s->regs[i] == ALLOC_NONE) {
      return i;
    }
  }

  return find_reg_to_spill(s, start, end, cur_ins);
}

static void maybe_free_reg(regalloc_state *s, uint16_t cur_idx, uint16_t idx,
                           bool keep_current_before) {
  auto next_idx = s->uses[idx];
  while (next_idx) {
    auto cur_use = s->next_uses[next_idx];
    if (cur_use.ir_idx < cur_idx ||
        (cur_use.ir_idx == cur_idx &&
         (!keep_current_before || !cur_use.before))) {
      next_idx = cur_use.next;
      continue;
    }
    break;
  }
  s->uses[idx] = next_idx;
  uint8_t reg = find_current_reg_for_value(s, idx);
  if (reg == REG_NONE) {
    return;
  }
  if (!next_idx) {
    s->regs[reg] = ALLOC_NONE;
  }
}

static void maybe_free_snapshot(regalloc_state *s, uint16_t cur_idx,
                                snap const *sn) {
  arr_for_each_idx(sn->slots, i) {
    auto val = sn->slots[i].val;
    if (!val.constant) {
      maybe_free_reg(s, cur_idx, val.loc, true);
    }
  }
}

static void materialize_arg_or_ensure_loc(regalloc_state *s, uint16_t cur_idx,
                                          ir_ins const *ins,
                                          uint16_t value_id) {
  auto in = &s->t->ins[value_id];
  uint8_t reg = find_current_reg_for_value(s, value_id);
  if (reg == REG_NONE) {
    assert(in->spill != SPILL_NONE);
    reg = find_free_reg(s, in->type == FLONUM_TAG, ins);
    s->regs[reg] = value_id;
    arrput(s->ops,
           ((reload_op){.ir_idx = cur_idx, .value_id = value_id, .reg = reg}));
  }

  arrput(
      s->dense_locs,
      ((dense_loc_entry){.kind = LOC_REG, .reg = reg, .value_id = value_id}));
}

static void init_regs(regalloc_state *s) {
  memset(s->regs, 0xff, sizeof(s->regs));
  bool unallocatable[MAX_REG] = {0};
  asm_init_unallocatable_regs(unallocatable);
  for (uint16_t i = 0; i < MAX_REG; i++) {
    if (unallocatable[i]) {
      s->regs[i] = ALLOC_UNALLOCATABLE;
    }
  }
}

static uint8_t find_initial_next_spill(trace *t) {
  uint8_t next_spill = 0;
  arr_for_each_idx(t->ins, i) {
    if (t->ins[i].spill != SPILL_NONE &&
        (uint16_t)t->ins[i].spill >= next_spill) {
      next_spill = (uint8_t)(t->ins[i].spill + 1);
    }
  }
  return next_spill;
}

static void assign_initial_spill_slots(regalloc_state *s) {
  arr_for_each_idx(s->t->ins, i) {
    if (!s->spilled[i] || s->t->ins[i].spill != SPILL_NONE) {
      continue;
    }
    if (s->next_spill == 255) {
      abort();
    }
    s->t->ins[i].spill = s->next_spill++;
  }
}

regalloc_result regalloc(trace *t) {
  regalloc_state s = {
      .t = t, .ir_id_to_dense_map = malloc(arrlen(t->ins) * sizeof(uint16_t))};
  init_regs(&s);
  collect_next_uses(&s);

  // PMOVs are pre-assigned spill slots and registers the parent trace.
  // Find next valid spill slot.
  size_t ins_len = arrlen(t->ins);
  size_t snap_idx = 0;
  size_t snap_len = arrlen(t->snaps);
  s.next_spill = find_initial_next_spill(t);
  assign_initial_spill_slots(&s);
  //print_ir(t, nullptr);

  for (size_t i = 0; i < ins_len; i++) {
    while (snap_idx < snap_len && t->snaps[snap_idx].ir == i) {
      if (snap_idx > 0) {
        maybe_free_snapshot(&s, (uint16_t)i, &t->snaps[snap_idx - 1]);
      }
      snap_idx++;
    }

    auto ins = &t->ins[i];
    slot args[3];
    uint8_t arg_count = collect_ir_args(t, ins, args);

    s.ir_id_to_dense_map[i] = arrlen(s.dense_locs);
    for (uint8_t arg = 0; arg < arg_count; arg++) {
      materialize_arg_or_ensure_loc(&s, (uint16_t)i, ins, args[arg].loc);
    }
    for (uint8_t arg = 0; arg < arg_count; arg++) {
      maybe_free_reg(&s, (uint16_t)i, args[arg].loc, false);
    }

    // Custom IR_PMOV handling
    if (ins->op == IR_PMOV) {
      if (ins->reg != REG_NONE && s.uses[i]) {
        s.regs[ins->prev_reg] = i;
      }
      continue;
    }
    if (ins->op == IR_REF) {
      continue;
    }
    if (s.uses[i] && ins->op != IR_PMOV) {
      auto res = find_free_reg(&s, ins->type == FLONUM_TAG, ins);
      ins->reg = res;
      s.regs[res] = i;
    }
    if (ins->op == IR_RET) {
      auto tmp = find_free_reg(&s, false, ins);
      arrput(s.dense_locs,
             ((dense_loc_entry){.kind = LOC_REG, .reg = tmp, .value_id = i}));
    }
  }

  regalloc_result out = {
      .reload_ops = s.ops,
      .dense_locs = s.dense_locs,
      .ir_id_to_dense_map = s.ir_id_to_dense_map,
      .spilled = s.spilled,
  };
  arrfree(s.next_uses);
  free(s.uses);
  return out;
}

void regalloc_result_free(regalloc_result *r) {
  arrfree(r->dense_locs);
  arrfree(r->reload_ops);
  free(r->ir_id_to_dense_map);
  free(r->spilled);
  memset(r, 0, sizeof(*r));
}
