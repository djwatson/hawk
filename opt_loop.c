#include "asm_x64.h" // for REG_NONE
#include "ir.h"      // for ir_ins, snap_s, snap_entry_s, trace_s, ir_ins_op
#include <assert.h>   // for assert
#include <stdint.h>   // for uint16_t
#include <stdio.h>    // for size_t, printf
#include <stdbool.h>
#include "third-party/stb_ds.h"

#define auto __auto_type
#define nullptr NULL

void opt_loop(trace_s *trace, int *regs) {
  auto cut = arrlen(trace->ops);
  auto snap_cut = arrlen(trace->snaps);
  uint16_t replace[cut * 2 + 1];
  for (unsigned i = 0; i < cut * 2 + 1; i++) {
    replace[i] = i;
  }

  {
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op = IR_LOOP;
    arrput(trace->ops, ins);
  }

  size_t* phis = NULL;
  unsigned long cur_snap = 0;
  for (size_t i = 0; i < cut + 1; i++) {
    // Emit phis last.
    if (i == cut) {
      for (uint64_t j = 0; j < arrlen(phis); j++) {
	unsigned long phi = phis[j];
        ir_ins ins;
        ins.reg = REG_NONE;
        ins.op = IR_PHI;
        ins.op1 = replace[phi];
        ins.op2 = replace[regs[trace->ops[phi].op1]];
        regs[trace->ops[phi].op1] = arrlen(trace->ops);
        replace[ins.op2] = arrlen(trace->ops);
        replace[ins.op1] = arrlen(trace->ops);
        arrput(trace->ops, ins);
      }
    }
    // Emit snaps, including any final snaps.
    while ((cur_snap < arrlen(trace->snaps)) &&
           (trace->snaps[cur_snap].ir == i)) {
      auto snap = &trace->snaps[cur_snap];

      if (cur_snap != 0) {
        snap_s nsnap;
        nsnap.ir = arrlen(trace->ops);
        nsnap.pc = snap->pc;
        nsnap.offset = snap->offset;
        nsnap.exits = 0;
        nsnap.link = -1;
        // Emit loopsnap - all final loop snapshots are carried through loop
        auto loopsnap = &trace->snaps[snap_cut - 1];
	for(uint64_t j = 0; j < arrlen(loopsnap->slots); j++) {
	  auto entry = &loopsnap->slots[j];
          if (entry->val < IR_CONST_BIAS) {
	    snap_entry_s new_entry = (snap_entry_s){entry->slot, replace[entry->val]};
            arrput(nsnap.slots, new_entry);
          } else {
	    arrput(nsnap.slots, *entry);
          }
        }
        // Emit in-loop snaps.  Merge with
	for(uint64_t j = 0; j < arrlen(snap->slots); j++) {
	  auto entry = &snap->slots[j];
          snap_entry_s new_entry;
          if (entry->val < IR_CONST_BIAS) {
            new_entry = (snap_entry_s){entry->slot, replace[entry->val]};
          } else {
            new_entry = *entry;
          }
          bool done = false;
	  for(uint64_t k = 0; j < arrlen(nsnap.slots); k++) {
	    auto nentry = &nsnap.slots[k];
            if (nentry->slot == new_entry.slot) {
              nentry->val = new_entry.val;
              done = true;
              break;
            }
          }
          if (!done) {
            arrput(nsnap.slots, (new_entry));
          }
        }
        arrput(trace->snaps, nsnap);
      }

      cur_snap++;
    }
    if (i == cut) {
      break;
    }
    auto ins = &trace->ops[i];
    switch (ins->op) {
    case IR_ARG:
    case IR_SLOAD: {
      assert(regs[ins->op1] >= 0);
      replace[i] = regs[ins->op1];
      printf("Potential phi: %zu %zu\n", i, arrlen(trace->ops));
      arrput(phis, i);
      break;
    }
    case IR_GE:
    case IR_ADD:
    case IR_EQ:
    case IR_NE:
    case IR_SUB: {
      ir_ins copy = *ins;
      if (copy.op1 < IR_CONST_BIAS) {
        copy.op1 = replace[copy.op1];
      }
      if (copy.op2 < IR_CONST_BIAS) {
        copy.op2 = replace[copy.op2];
      }
      replace[i] = arrlen(trace->ops);
      arrput(trace->ops, copy);
      break;
    }
    case IR_GGET: {
      ir_ins copy = *ins;
      if (copy.op1 < IR_CONST_BIAS) {
        copy.op1 = replace[copy.op1];
      }
      replace[i] = arrlen(trace->ops);
      arrput(trace->ops, copy);
      break;
    }
    default: {
      printf("Can't loop ir type: %s\n", ir_names[(int)ins->op]);
      arrsetlen(trace->ops, cut);
      arrsetlen(trace->snaps, snap_cut);
      return;
    }
    }
  }
}
