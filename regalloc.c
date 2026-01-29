#include "regalloc.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asm.h"
#include "hawk.h"
#include "ir.h"

// Reverse linear scan register allocation.  Since it's (mostly) a linear trace,
// it's quite simple.

// For spilling, we just heuristically spill the least used slot.

// For snapshots, if ANY ir in a snapshot was EVER spilled, we must use the
// spill slot (since there are no joins, and the register was reused).

typedef struct {
  uint16_t s;
  bool used;
  uint16_t last_use;
} regmap;

typedef struct regalloc_state {
  regmap regs[MAX_REG];
  uint32_t next_spill;
  trace *t;
  reload_info *reloads;
} regalloc_state;

static inline bool ins_uses_freg(ir_ins const *ins) {
  return ins->type == FLONUM_TAG;
}

static inline ir_ins *slot_ins(trace *t, slot v) {
  assert(!v.constant);
  return &t->ins[v.loc];
}

static uint8_t assign_spill(regalloc_state *s);

static int alloc_gpr(regalloc_state *s) {
  for (int i = 0; i < FPR_REG_START; i++) {
    if (!s->regs[i].used) {
      return i;
    }
  }
  return REG_NONE;
}

static int alloc_fpr(regalloc_state *s) {
  for (int i = FPR_REG_START; i < FPR_REG_END; i++) {
    if (!s->regs[i].used) {
      return i;
    }
  }
  return REG_NONE;
}

static int spill_gpr(regalloc_state *s, uint16_t reload_at) {
  int victim = REG_NONE;
  uint16_t farthest_use = 0;
  for (int i = 0; i < FPR_REG_START; i++) {
    if (!s->regs[i].used) {
      continue;
    }
    if (victim == REG_NONE || s->regs[i].last_use > farthest_use) {
      victim = i;
      farthest_use = s->regs[i].last_use;
    }
  }
  assert(victim != REG_NONE);
  auto ir = &s->t->ins[s->regs[victim].s];
  if (ir->spill == SPILL_NONE) {
    ir->spill = assign_spill(s);
  }
  s->regs[victim].used = false;
  arrput(nullptr, s->reloads,
         ((reload_info){(uint16_t)victim, reload_at, s->regs[victim].s}));
  return victim;
}

static int spill_fpr(regalloc_state *s, uint16_t reload_at) {
  int victim = REG_NONE;
  uint16_t farthest_use = 0;
  for (int i = FPR_REG_START; i < FPR_REG_END; i++) {
    if (!s->regs[i].used) {
      continue;
    }
    if (victim == REG_NONE || s->regs[i].last_use > farthest_use) {
      victim = i;
      farthest_use = s->regs[i].last_use;
    }
  }
  assert(victim != REG_NONE);
  auto ir = &s->t->ins[s->regs[victim].s];
  if (ir->spill == SPILL_NONE) {
    ir->spill = assign_spill(s);
  }
  s->regs[victim].used = false;
  arrput(nullptr, s->reloads,
         ((reload_info){(uint16_t)victim, reload_at, s->regs[victim].s}));
  return victim;
}

static uint8_t assign_spill(regalloc_state *s) {
  auto ret = (s->next_spill)++;
  assert(s->next_spill < 255);
  return ret;
}

static inline uint8_t slot_reg(trace *t, slot v) {
  return v.constant ? REG_NONE : slot_ins(t, v)->reg;
}

static void assign_snap_registers(regalloc_state *s, size_t snap_num,
                                  trace *t) {
  // Get a free register, if any.  If already assigned a slot, do nothing.
  // If no free registers, assign a slot.
  auto snap = &t->snaps[snap_num];
  arr_for_each_idx(snap->slots, i) {
    auto sl = &snap->slots[i];
    if (sl->val.constant) {
      continue;
    }
    auto op = &t->ins[sl->val.loc];
    if (op->reg != REG_NONE || op->spill != SPILL_NONE) {
      continue;
    }
    // Try and find a free reg, or assign the next spill slot.
    if (ins_uses_freg(op)) {
      op->reg = (uint8_t)alloc_fpr(s);
    } else {
      op->reg = (uint8_t)alloc_gpr(s);
    }
    if (op->reg == REG_NONE) {
      // Couldn't find a free reg, assign a slot.
      op->spill = assign_spill(s);
    } else {
      s->regs[op->reg].s = sl->val.loc;
      s->regs[op->reg].used = true;
    }
  }
}

static void maybe_assign_register(regalloc_state *s, slot v,
                                  uint16_t reload_at) {
  if (!v.constant) {
    auto op = &s->t->ins[v.loc];
    if (op->reg == REG_NONE) {
      op->reg =
          ins_uses_freg(op) ? (uint8_t)alloc_fpr(s) : (uint8_t)alloc_gpr(s);
      if (op->reg == REG_NONE) {
        op->reg = ins_uses_freg(op) ? (uint8_t)spill_fpr(s, reload_at)
                                    : (uint8_t)spill_gpr(s, reload_at);
      }
      s->regs[op->reg].s = v.loc;
      s->regs[op->reg].used = true;
    }
    s->regs[op->reg].last_use = op - s->t->ins;
  }
}

// TODO: once spilling happens, we need to return op1/op2 and tmp register
// assignments at EACH USE.
regalloc_result regalloc(trace *t) {
  regalloc_state s = {0};
  s.t = t;
  size_t ins_len = arrlen(t->ins);
  reg_binding *bindings = malloc(ins_len * sizeof(reg_binding));
  memset(bindings, 0xff, ins_len * sizeof(reg_binding));

  // Set up register allocator.
  bool reserved[MAX_REG] = {0};
  asm_mark_unallocatable(reserved);
  for (int i = 0; i < MAX_REG; i++) {
    s.regs[i].used = reserved[i];
    s.regs[i].last_use = reserved[i] ? 0 : -1;
  }
  // TODO move this back to asm backends?
  s.regs[FRTMP].used = true;

  // Assign loopback snap registers.
  int32_t cur_snap = (int32_t)arrlen(t->snaps) - 1;
  assign_snap_registers(&s, cur_snap, t);
  auto op_cnt_idx = arrlen(t->ins);
  for (; op_cnt_idx > 0; op_cnt_idx--) {
    uint16_t op_cnt = op_cnt_idx - 1;
    while (cur_snap >= 0 && t->snaps[cur_snap].ir > op_cnt) {
      if (cur_snap > 0) {
        // Assign snap registers.
        assign_snap_registers(&s, cur_snap - 1, t);
      }
      cur_snap--;
    }
    auto op = &t->ins[op_cnt];

    // If we need to spill, ensure we have a tmp reg.
    if (op->reg == REG_NONE && op->spill != SPILL_NONE) {
      maybe_assign_register(&s, (slot){.constant = false, .loc = op_cnt},
                            op_cnt);
    }

    // free current register.  We don't free IR_ARG since they are all
    // live on entry.
    if (op->reg != REG_NONE && op->op != IR_ARG) {
      assert(s.regs[op->reg].s == op_cnt);
      s.regs[op->reg].used = false;
    }

    switch (op->op) {
    case IR_GUARD_EQ:
    case IR_EQ:
    case IR_NE:
    case IR_LT:
    case IR_GT:
    case IR_GTE:
    case IR_SUB:
    case IR_ADD:
      maybe_assign_register(&s, op->op1, op_cnt);
      maybe_assign_register(&s, op->op2, op_cnt);
      bindings[op_cnt].arg[0].reg = slot_reg(t, op->op1);
      bindings[op_cnt].arg[1].reg = slot_reg(t, op->op2);
      break;
    case IR_LOAD:
    case IR_TYPECHECK:
      maybe_assign_register(&s, op->op1, op_cnt);
      bindings[op_cnt].arg[0].reg = slot_reg(t, op->op1);
      break;
    case IR_STORE:
      auto ref = slot_ins(t, op->op1);
      uint16_t ref_idx = op->op1.loc;
      assert(ref->op == IR_REF);
      maybe_assign_register(&s, ref->op1, op_cnt);
      maybe_assign_register(&s, ref->op2, op_cnt);
      maybe_assign_register(&s, op->op2, op_cnt);
      bindings[op_cnt].arg[1].reg = slot_reg(t, op->op2);
      bindings[ref_idx].arg[0].reg = slot_reg(t, ref->op1);
      bindings[ref_idx].arg[1].reg = slot_reg(t, ref->op2);
      if (!ref->op2.constant) {
        // Need a tmp reg
        maybe_assign_register(&s, (slot){.constant = false, .loc = op_cnt},
                              op_cnt);
        s.regs[op->reg].used = false;
      }

      break;
    case IR_RET:
      // Ret requires a tmp reg.  Alloc one and immediately free it.
      // TODO: actually since there is NEVER anything after ret, we can choose
      // any reg.
      maybe_assign_register(&s, (slot){.constant = false, .loc = op_cnt},
                            op_cnt);
      s.regs[op->reg].used = false;
      break;
    case IR_ALLOC: // currently only constants supported.
    case IR_REF:
    case IR_SLOAD:
    case IR_GGET:
    case IR_ARG:
    case IR_NOP:
    case IR_PMOV:
      break;
    default:
      abort();
    }
  }

  arr_reverse(s.reloads);
  return (regalloc_result){.bindings = bindings, .reloads = s.reloads};
}
