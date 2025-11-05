#include <capstone/capstone.h> // for cs_insn, cs_close, cs_disasm, cs_free

#include <assert.h>
#include <string.h>
#include <sys/mman.h>

#include "asm_x64.h"
#include "disassemble.h"
#include "ir.h"

typedef struct {
  uint16_t s;
  bool used;
} regmap;

static void assign_snap_registers(size_t snap_num, regmap *regs, trace *t,
                                  uint32_t *next_spill) {
  // Get a free register, if any.  If already assigned a slot, do nothing.
  // If no free registers, assign a slot.
  auto snap = &t->snaps[snap_num];
  for (uint64_t i = 0; i < arrlen_snap_entry(snap->slots); i++) {
    auto s = &snap->slots[i];
    if (s->val.constant) {
      continue;
    }
    auto op = &t->ins[s->val.loc];
    if (op->reg != REG_NONE || op->spill != SPILL_NONE) {
      continue;
    }
    // Try and find a free reg, or assign the next spill slot.
    bool done = false;
    for (int j = 0; j < MAX_REG; j++) {
      if (!regs[j].used) {
        op->reg = j;
        regs[op->reg].s = s->val.loc;
        regs[op->reg].used = true;
        done = true;
        // lru_poke(&reg_lru, op->reg);
        /* printf("Assigning snap register %s to op %i\n",
         * reg_names[op->reg], s->val); */
        break;
      }
    }
    if (!done) {
      // Couldn't find a free reg, assign a slot.
      op->spill = (*next_spill)++;
      /* printf("Assigning snap slot %i to op %i\n", op->slot, s->val); */
      assert(*next_spill < 255);
      // check_spill_cnt(*next_spill);
    }
  }
}
// Get a specific reg, spilling if necessary.
static void get_reg(uint8_t reg, trace *trace, uint32_t *next_spill,
                    regmap *slot) {
  if (slot[reg].used) {
    /* // printf("Spilling reg %s\n", reg_names[reg]); */
    /* auto op = slot[reg]; */
    /* assert(trace->ops[op].reg != REG_NONE); */

    /* auto spill = trace->ops[op].slot; */
    /* if (trace->ops[op].slot == SLOT_NONE) { */
    /*   spill = (*next_spill)++; */
    /*   check_spill_cnt(*next_spill); */
    /* } */

    /* trace->ops[op].slot = spill; */
    /* emit_mem_reg(OP_MOV_MR, 0, R15, trace->ops[op].reg); */
    /* emit_mov64(R15, (int64_t)&spill_slot[trace->ops[op].slot]); */
    /* trace->ops[op].reg = REG_NONE; */
    /* slot[reg] = -1; */
    /* lru_poke(&reg_lru, reg); */
    abort();
  }
  slot[reg].used = true;
}
static int get_free_reg(trace *trace, uint32_t *next_spill, regmap *slot,
                        bool callee) {
  for (int i = 0; i < MAX_REG; i++) {
    if (!slot[i].used) {
      return i;
    }
  }

  abort();
  // Spill.

  // get_reg(oldest, trace, next_spill, slot);
  // return oldest;
}
static void maybe_assign_register(slot v, trace *trace, regmap *slot,
                                  uint32_t *next_spill) {
  if (!v.constant) {
    auto op = &trace->ins[v.loc];
    if (op->reg == REG_NONE) {
      op->reg = get_free_reg(trace, next_spill, slot, false);
      slot[op->reg].s = v.loc;
      slot[op->reg].used = true;
    }
    // TODO
    // lru_poke(&reg_lru, op->reg);
  }
}

void emit(trace *t) {
  // TODO move init somewhere else
  emit_init();
  regmap reg_to_slot[MAX_REG];
  memset(reg_to_slot, 0, sizeof(reg_to_slot));

  // Unallocatable.
  reg_to_slot[R15].used = true;
  reg_to_slot[RSP].used = true;
  reg_to_slot[RDI].used = true;
  reg_to_slot[RBX].used = true;

  long *snap_labels = malloc(sizeof(long) * arrlen_snap(t->snaps));
  auto end = emit_offset();
  emit_ret();
  restore_callee_regs();
  auto exit_label = emit_offset();
  for (uint64_t i = arrlen_snap(t->snaps); i > 0; i--) {
    snap *snap = &t->snaps[i - 1];
    emit_jmp32((int32_t)(exit_label - emit_offset()));
    // TODO this needs to be a FLUSH of the snapshot.
    emit_mov64(RET_REG, i - 1);
    snap_labels[i - 1] = emit_offset();
  }

  // TODO
  // loopback emit, or jump to exit
  // for loopback:
  // don't forget to store snap below, and
  // update stack ptr
  // checking for stack size (eventually)

  // No loopback to start:
  emit_jmp32(
      (int32_t)(snap_labels[(arrlen_snap(t->snaps) - 1)] - emit_offset()));

  size_t cur_snap = arrlen_snap(t->snaps) - 1;
  auto op_cnt_idx = arrlen_ins(t->ins);
  uint32_t next_spill = 0;
  assign_snap_registers(cur_snap, reg_to_slot, t, &next_spill);
  bool done = false;
  for (; op_cnt_idx > 0 && !done; op_cnt_idx--) {
    uint16_t op_cnt = op_cnt_idx - 1;
    while (cur_snap >= 0 && t->snaps[cur_snap].ir > op_cnt) {
      if (cur_snap > 0) {
        assign_snap_registers(cur_snap - 1, reg_to_slot, t, &next_spill);
      }
      cur_snap--;
    }
    auto op = &t->ins[op_cnt];

    // Check for spill
    if (op->spill != SPILL_NONE) {
      if (op->reg == REG_NONE) {
        maybe_assign_register((slot){.constant = false, .loc = op_cnt}, t,
                              reg_to_slot, &next_spill);
      }
      // printf("Spilling op %li to slot %i from reg %s\n", op_cnt, op->slot,
      // reg_names[op->reg]);
      abort();
      /* emit_mem_reg(OP_MOV_RM, 0, R15, op->reg); */
      /* emit_mov64(R15, (int64_t)&spill_slot[op->slot]); */
    }
    /* if (op->reg == REG_NONE) { */
    /*   printf("WARNING: emitting op with no reg: %i\n", op_cnt); */
    /* } */

    // free current register.
    if (op->reg != REG_NONE && op->reg != RDI && op->op != IR_ARG) {
      assert(reg_to_slot[op->reg].s == op_cnt);
      reg_to_slot[op->reg].used = false;
    }

    emit_check();
    switch (op->op) {
    case IR_GUARD_EQ: {
      maybe_assign_register(op->op1, t, reg_to_slot, &next_spill);
      maybe_assign_register(op->op2, t, reg_to_slot, &next_spill);
      assert(!op->op2.constant);
      uint8_t reg = R15;
      if (!op->op1.constant) {
        reg = t->ins[op->op1.loc].reg;
      }
      emit_jcc32(JNE, snap_labels[cur_snap]);
      emit_reg_reg(ASM_CMP, reg, t->ins[op->op2.loc].reg);
      if (op->op1.constant) {
        emit_mov64(R15, t->consts[op->op1.loc].value);
      }
      break;
    }
    case IR_LOAD: {
      maybe_assign_register(op->op1, t, reg_to_slot, &next_spill);
      assert(!op->op1.constant);
      emit_mem_reg(ASM_MOV_MR, (uint16_t)op->op2.loc + 8,
                   t->ins[op->op1.loc].reg, op->reg);
      break;
    }
    case IR_LT: {
      maybe_assign_register(op->op1, t, reg_to_slot, &next_spill);
      maybe_assign_register(op->op2, t, reg_to_slot, &next_spill);
      assert(!op->op1.constant);
      uint8_t op2_reg = R15;
      if (!op->op2.constant) {
        op2_reg = t->ins[op->op1.loc].reg;
      }

      auto lt_fin = emit_offset();
      emit_mov64(op->reg, TRUE_REP.value);
      auto tr = emit_offset();
      // whacky why does jmp32 take absolute, and jcc32 take relative?
      // TODO make this set instead?
      emit_jmp32(lt_fin - emit_offset());
      emit_mov64(op->reg, FALSE_REP.value);
      emit_jcc32(JL, tr);
      emit_reg_reg(ASM_CMP, op2_reg, t->ins[op->op1.loc].reg);
      if (op->op2.constant) {
        emit_mov64(R15, t->consts[op->op2.loc].value);
      }
      break;
    }
    case IR_SUB: {
      maybe_assign_register(op->op1, t, reg_to_slot, &next_spill);
      maybe_assign_register(op->op2, t, reg_to_slot, &next_spill);
      assert(!op->op1.constant);
      uint8_t reg = R15;
      if (!op->op2.constant) {
        reg = t->ins[op->op2.loc].reg;
      } else {
        assert(t->ins[op->op2.loc].reg != op->reg);
      }
      emit_reg_reg(ASM_SUB, reg, op->reg);
      if (t->ins[op->op1.loc].reg != op->reg) {
        emit_reg_reg(ASM_MOV, t->ins[op->op1.loc].reg, op->reg);
      }
      if (op->op2.constant) {
        emit_mov64(R15, t->consts[op->op2.loc].value);
      }
      break;
    }
    case IR_SLOAD: {
      emit_mem_reg(ASM_MOV_MR, op->data * 8, RDI, op->reg);
      break;
    }
    case IR_GGET: {
      break;
    }
    default: {
      printf("Can't jit op: %s\n", ir_names[op->op]);
      // exit(-1);
    }
    }
  }
  free(snap_labels);
  // emit parcopy from loop end
  // parcopy from parent trace?
  save_callee_regs();

  auto sz = end - emit_offset();
  disassemble((uint8_t *)emit_offset(), sz);
  // emit and done
  // patch if side trace
}
