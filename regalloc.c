#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "asm.h"
#include "ir.h"

// Reverse linear scan register allocation.  Since it's (mostly) a linear trace,
// it's quite simple.

// For spilling, we just heuristically spill the least used slot.

// For snapshots, if ANY ir in a snapshot was EVER spilled, we must use the
// spill slot (since there are no joins, and the register was reused).

typedef struct {
  uint16_t s;
  bool used;
} regmap;

typedef struct regalloc_state {
  regmap regs[MAX_REG];
  uint32_t next_spill;
} regalloc_state;

static inline bool ins_uses_freg(ir_ins const *ins) {
  return ins->type == FLONUM_TAG;
}

static inline ir_ins *slot_ins(trace *t, slot v) {
  assert(!v.constant);
  return &t->ins[v.loc];
}

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
      op->spill = (s->next_spill)++;
      /* printf("Assigning snap slot %i to op %i\n", op->slot, sl->val); */
      assert(s->next_spill < 255);
      // check_spill_cnt(s->next_spill);
    } else {
      s->regs[op->reg].s = sl->val.loc;
      s->regs[op->reg].used = true;
    }
  }
}
// Get a specific reg, spilling if necessary.
/* static void get_reg(emit_state *s, uint8_t reg, trace *trace) { */
/*   if (s->regs[reg].used) { */
/*     /\* // printf("Spilling reg %s\n", reg_names[reg]); *\/ */
/*     /\* auto op = s->regs[reg]; *\/ */
/*     /\* assert(trace->ops[op].reg != REG_NONE); *\/ */

/*     /\* auto spill = trace->ops[op].slot; *\/ */
/*     /\* if (trace->ops[op].slot == SLOT_NONE) { *\/ */
/*     /\*   spill = (s->next_spill)++; *\/ */
/*     /\*   check_spill_cnt(s->next_spill); *\/ */
/*     /\* } *\/ */

/*     /\* trace->ops[op].slot = spill; *\/ */
/*     /\* emit_mem_reg(OP_MOV_MR, 0, RTMP, trace->ops[op].reg); *\/ */
/*     /\* emit_mov64(RTMP, (int64_t)&spill_slot[trace->ops[op].slot]); *\/ */
/*     /\* trace->ops[op].reg = REG_NONE; *\/ */
/*     /\* s->regs[reg] = -1; *\/ */
/*     /\* lru_poke(&reg_lru, reg); *\/ */
/*     abort(); */
/*   } */
/*   s->regs[reg].used = true; */
/* } */
static void maybe_assign_register(regalloc_state *s, slot v, trace *t) {
  if (!v.constant) {
    auto op = &t->ins[v.loc];
    if (op->reg == REG_NONE) {
      op->reg =
          ins_uses_freg(op) ? (uint8_t)alloc_fpr(s) : (uint8_t)alloc_gpr(s);
      if (op->reg == REG_NONE) {
        printf("TODO MUST IMPLEMENT REG SPILLING\n");
        abort();
      }
      s->regs[op->reg].s = v.loc;
      s->regs[op->reg].used = true;
    }
    // TODO
    // lru_poke(&reg_lru, op->reg);
  }
}

// TODO: once spilling happens, we need to return op1/op2 and tmp register
// assignments at EACH USE.
void regalloc(trace *t) {
  regalloc_state s = {0};

  // Set up register allocator.
  bool reserved[MAX_REG] = {0};
  asm_mark_unallocatable(reserved);
  for (int i = 0; i < MAX_REG; i++) {
    s.regs[i].used = reserved[i];
  }
  // TODO move this back to asm backends?
  s.regs[FRTMP].used = true;

  int32_t cur_snap = (int32_t)arrlen(t->snaps) - 1;
  assign_snap_registers(&s, cur_snap, t);
  auto op_cnt_idx = arrlen(t->ins);
  for (; op_cnt_idx > 0; op_cnt_idx--) {
    uint16_t op_cnt = op_cnt_idx - 1;
    while (cur_snap >= 0 && t->snaps[cur_snap].ir > op_cnt) {
      if (cur_snap > 0) {
        assign_snap_registers(&s, cur_snap - 1, t);
      }
      cur_snap--;
    }
    auto op = &t->ins[op_cnt];

    // Check for spill
    if (op->spill != SPILL_NONE) {
      // printf("Spilling op %li to slot %i from reg %s\n", op_cnt, op->slot,
      // reg_names[op->reg]);
      abort();
      /* emit_mem_reg(OP_MOV_RM, 0, RTMP, op->reg); */
      /* emit_mov64(RTMP, (int64_t)&spill_slot[op->slot]); */
    }

    // Assign reg to this if it doesn't have a reg yet.
    if (op->op == IR_RET) {
      maybe_assign_register(&s, (slot){.constant = false, .loc = op_cnt}, t);
    }
    // free current register.
    if (op->reg != REG_NONE && op->op != IR_ARG) {
      if (op->reg != RSTACK) {
        assert(s.regs[op->reg].s == op_cnt);
        s.regs[op->reg].used = false;
      }
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
      maybe_assign_register(&s, op->op1, t);
      maybe_assign_register(&s, op->op2, t);
      break;
    case IR_LOAD:
      maybe_assign_register(&s, op->op1, t);
      break;
    case IR_STORE:
      auto ref = slot_ins(t, op->op1);
      assert(ref->op == IR_REF);
      maybe_assign_register(&s, ref->op1, t);
      maybe_assign_register(&s, ref->op2, t);
      maybe_assign_register(&s, op->op2, t);
      if (!ref->op2.constant) {
        // Need a tmp reg
        maybe_assign_register(&s, (slot){.constant = false, .loc = op_cnt}, t);
        s.regs[op->reg].used = false;
      }

      break;
    case IR_ALLOC:
      // tmp reg required
      if (op->reg == REG_NONE) {
        maybe_assign_register(&s, (slot){.constant = false, .loc = op_cnt}, t);
      }
      break;
    case IR_REF:
    case IR_SLOAD:
    case IR_GGET:
    case IR_RET:
    case IR_ARG:
    case IR_NOP:
    case IR_PMOV:
      break;
    case IR_TYPECHECK:
      maybe_assign_register(&s, op->op1, t);
      break;
    default:
      abort();
    }
  }
}
