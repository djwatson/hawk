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

#define ALLOC_NONE UINT16_MAX
#define ALLOC_UNALLOCATABLE (UINT16_MAX - 1)

// A simple two-pass register allocator: The first pass collects
// next-use chains, and calculates register pressure, and picks spills.
//
// The forward pass, that is integrated in to emit.c, then actually
// chooses registers.  Potential spill candidates are pre-computed,
// but it still has some freedom to perhaps pick a better spill based
// on next-use.

// (TODO: investigate if dropping next-use chains entirely, and having the
// backwards walk emit where some irs are 'spilled', i.e. no longer in register,
// is worthwhile - unclear if next-use chains pay for themselves or not).

// This is very similar to 'SSA-based' register allocation, where spilling and
// register allocation are separate.

// We're slightly more complicated than LuaJIT here, because instead
// of a single backwards pass, we're emitting code forward (both for
// clarity, and to make loopback register parallel copies easier).

static void limit_live_values(regalloc_state *s, lru *lru, uint16_t max) {
  while (lru->count > max) {
    uint16_t spill_value = lru_pop_oldest(lru);
    auto ins = &s->t->ins[spill_value];
    if (ins->spill == SPILL_NONE) {
      if (s->next_spill == 255) {
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

static bool ir_is_vm_call(ir_ins_op op) {
  switch (op) {
  case IR_VMADD:
  case IR_VMSUB:
  case IR_VMMUL:
  case IR_VMDIV:
  case IR_VMQUOTIENT:
  case IR_VMMOD:
  case IR_VMLT:
  case IR_VMGT:
  case IR_VMLTE:
  case IR_VMGTE:
  case IR_VMJEQV:
  case IR_VMJNEQV:
  case IR_VMINEXACT:
  case IR_VMEXACT:
  case IR_VMTRUNCATE:
    return true;
  default:
    return false;
  }
}

static uint8_t regalloc_collect_carg_args(trace const *t, slot chain, slot *args) {
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
  return (uint8_t)(count + regalloc_collect_carg_args(t, carg->op2, args + count));
}

static const char *regalloc_foreign_type_name(gc_obj type_obj) {
  if (!is_symbol(type_obj)) {
    abort();
  }
  auto name = get_sym_name(to_symbol(type_obj));
  if (!name) {
    abort();
  }
  return name->str;
}

static void regalloc_ccall_limits(trace const *t, ir_ins const *ins,
                                  uint16_t *gpr_limit, uint16_t *fpr_limit) {
  uint16_t gpr = 0;
  uint16_t fpr = 0;
  gc_obj sig_obj = t->consts[ins->op1.loc];
  gc_obj arg_types = to_cons(to_cons(to_cons(sig_obj)->b)->b)->a;
  while (arg_types.value != NIL_TAG) {
    if (!is_cons(arg_types)) {
      abort();
    }
    auto entry = to_cons(arg_types);
    if (strcmp(regalloc_foreign_type_name(entry->a), "double") == 0) {
      fpr++;
    } else {
      gpr++;
    }
    arg_types = entry->b;
  }
  if (ins->type == FLONUM_TAG) {
    fpr++;
  } else {
    gpr++;
  }
  *gpr_limit = gpr;
  *fpr_limit = fpr;
}

uint8_t regalloc_collect_ir_args(trace const *t, ir_ins const *ins,
                                 slot *args) {
  uint8_t count = 0;
  slot op1 = ins->op1;
  slot op2 = ins->op2;
  if (ins->op == IR_STORE || ins->op == IR_STORE_CHAR) {
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

static void add_next_use(regalloc_state *s, uint16_t loc, uint16_t ir_idx,
                         bool before, bool is_snap) {
  auto next = (next_use){.ir_idx = ir_idx,
                         .before = before,
                         .is_snap = is_snap,
                         .next = s->uses[loc]};
  s->uses[loc] = (uint32_t)arrlen(s->next_uses);
  arrput(s->next_uses, next);
}

void regalloc_collect_next_uses(regalloc_state *s) {
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
          bool flonum = s->t->ins[val.loc].type == FLONUM_TAG;
          auto value_lru = flonum ? &fpr_live : &gpr_live;
          lru_add(value_lru, val.loc);
          limit_live_values(s, value_lru,
                            flonum ? FPR_ALLOCATABLE : GPR_ALLOCATABLE);
        }
      }
      cur_snap_end_ir = cur->ir;
    }

    auto value_lru =
        s->t->ins[value_id].type == FLONUM_TAG ? &fpr_live : &gpr_live;
    lru_remove(value_lru, value_id);

    auto ins = &s->t->ins[value_id];
    if (ins->op == IR_CCALL || ir_is_vm_call(ins->op)) {
      limit_live_values(s, &gpr_live, 0);
      limit_live_values(s, &fpr_live, 0);
    }

    slot args[UINT8_MAX];
    uint8_t arg_count = regalloc_collect_ir_args(s->t, ins, args);
    for (uint8_t arg = 0; arg < arg_count; arg++) {
      add_next_use(s, args[arg].loc, value_id, true, false);
      auto arg_lru =
          s->t->ins[args[arg].loc].type == FLONUM_TAG ? &fpr_live : &gpr_live;
      lru_poke(arg_lru, args[arg].loc);
    }
    // In the current regalloc, the output register is live
    // at the same time as the input registers.
    uint16_t gpr_limit = GPR_ALLOCATABLE;
    uint16_t fpr_limit = FPR_ALLOCATABLE;
    if (s->t->ins[value_id].type == FLONUM_TAG) {
      fpr_limit--;
    } else if (ins->op != IR_REF && ins->op != IR_CARG) {
      gpr_limit--;
    }
    // RET requires a tmp reg.
    if (ins->op == IR_RET) {
      gpr_limit--;
    }
    limit_live_values(s, &gpr_live, gpr_limit);
    limit_live_values(s, &fpr_live, fpr_limit);
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

static bool value_used_by_ir_ins(trace const *t, ir_ins const *ins,
                                 uint16_t value_id) {
  slot args[UINT8_MAX];
  uint8_t arg_count = regalloc_collect_ir_args(t, ins, args);
  for (uint8_t arg = 0; arg < arg_count; arg++) {
    if (args[arg].loc == value_id) {
      return true;
    }
  }
  return false;
}

uint8_t regalloc_find_free_reg(regalloc_state *s, bool flonum,
                               ir_ins const *cur_ins) {
  uint16_t start = flonum ? FPR_REG_START : 0;
  uint16_t end = flonum ? FPR_REG_END : FPR_REG_START;
  uint16_t spill_reg = UINT16_MAX;
  uint32_t farthest_use = 0;
  bool have_candidate = false;
  for (uint16_t i = start; i < end; i++) {
    if (s->regs[i] == ALLOC_UNALLOCATABLE) {
      continue;
    }
    if (s->regs[i] == ALLOC_NONE) {
      return (uint8_t)i;
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
  return (uint8_t)spill_reg;
}

void regalloc_maybe_free_reg(regalloc_state *s, uint16_t cur_idx, uint16_t idx,
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
  uint8_t reg = regalloc_find_current_reg_for_value(s, idx);
  if (reg == REG_NONE) {
    return;
  }
  if (!next_idx) {
    s->regs[reg] = ALLOC_NONE;
  }
}

void regalloc_maybe_free_snapshot(regalloc_state *s, uint16_t cur_idx,
                                  snap const *sn) {
  arr_for_each_idx(sn->slots, i) {
    auto val = sn->slots[i].val;
    if (!val.constant) {
      regalloc_maybe_free_reg(s, cur_idx, val.loc, true);
    }
  }
}

uint8_t regalloc_materialize_arg_or_ensure_loc(regalloc_state *s,
                                               uint16_t cur_idx,
                                               ir_ins const *ins,
                                               uint16_t value_id) {
  (void)cur_idx;
  auto in = &s->t->ins[value_id];
  uint8_t reg = regalloc_find_current_reg_for_value(s, value_id);
  if (reg == REG_NONE) {
    assert(in->spill != SPILL_NONE);
    reg = regalloc_find_free_reg(s, in->type == FLONUM_TAG, ins);
    s->regs[reg] = value_id;
  }
  return reg;
}

void regalloc_assign_output(regalloc_state *s, uint16_t ir_idx, ir_ins *ins) {
  if (ins->op == IR_PMOV) {
    if (ins->reg != REG_NONE && s->uses[ir_idx]) {
      s->regs[ins->prev_reg] = ir_idx;
    }
    return;
  }
  if (ins->op == IR_REF || ins->op == IR_CARG || !s->uses[ir_idx]) {
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
      s->next_spill = (uint8_t)(t->ins[i].spill + 1);
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
  regalloc_collect_next_uses(s);
}

void regalloc_state_free(regalloc_state *s) {
  arrfree(s->next_uses);
  free(s->uses);
  memset(s, 0, sizeof(*s));
}
