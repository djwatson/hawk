#include <capstone/capstone.h> // for cs_insn, cs_close, cs_disasm, cs_free

#include <sys/mman.h>
#include <string.h>
#include <assert.h>

#include "ir.h"
#include "x64.h"
#include "disassemble.h"

typedef struct {
  uint16_t s;
  bool used;
} regmap;

static void assign_snap_registers(size_t cur_snap , regmap* regs, trace* t, uint32_t *next_spill) {}
static void maybe_assign_register(uint16_t v, trace *trace, regmap *slot,
                                  uint32_t *next_spill) {}

void emit(trace* t) {
  // TODO move init somewhere else
  emit_init();
  regmap reg_to_slot[MAX_REG];
  memset(reg_to_slot, 0, sizeof(reg_to_slot));

  // Unallocatable.
  reg_to_slot[R15].used = true;
  reg_to_slot[RSP].used = true;
  reg_to_slot[RDI].used = true;
  reg_to_slot[RBX].used = true;


  long*snap_labels = malloc(sizeof(long) * arrlen_snap(t->snaps));
  auto end = emit_offset();
  emit_ret();
  restore_callee_regs();
  auto exit_label = emit_offset();
  for(uint64_t i = arrlen_snap(t->snaps); i > 0; i--) {
    snap* snap = &t->snaps[i-1];
    emit_jmp32((int32_t)(exit_label - emit_offset()));
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
  emit_jmp32((int32_t)(snap_labels[(arrlen_snap(t->snaps)-1)] - emit_offset()));
  
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
        maybe_assign_register(op_cnt, t, reg_to_slot, &next_spill);
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
      default: {
      printf("Can't jit op: %s\n", ir_names[op->op]);
      //exit(-1);
      }
    }
  }
  free(snap_labels);
  // emit parcopy from loop end
  // parcopy from parent trace?
  save_callee_regs();

  auto sz = end - emit_offset();
  disassemble((uint8_t*)emit_offset(), sz);
  // emit and done
  // patch if side trace
}
