#include "asm_x64.h" // for REG_NONE
#include "ir.h"      // for ir_ins, snap_s, snap_entry_s, trace_s, ir_ins_op
#include <cassert>   // for assert
#include <cstdint>   // for uint16_t
#include <cstdio>    // for size_t, printf
#include <memory>    // for allocator_traits<>::value_type
#include <vector>    // for vector
#include "third-party/stb_ds.h"

void opt_loop(trace_s *trace, int *regs) {
  auto cut = trace->ops.size();
  auto snap_cut = arrlen(trace->snaps);
  uint16_t replace[cut * 2 + 1];
  for (unsigned i = 0; i < cut * 2 + 1; i++) {
    replace[i] = i;
  }

  {
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op = ir_ins_op::LOOP;
    trace->ops.push_back(ins);
  }

  std::vector<size_t> phis;
  unsigned long cur_snap = 0;
  for (size_t i = 0; i < cut + 1; i++) {
    // Emit phis last.
    if (i == cut) {
      for (unsigned long phi : phis) {
        ir_ins ins;
        ins.reg = REG_NONE;
        ins.op = ir_ins_op::PHI;
        ins.op1 = replace[phi];
        ins.op2 = replace[regs[trace->ops[phi].op1]];
        regs[trace->ops[phi].op1] = trace->ops.size();
        replace[ins.op2] = trace->ops.size();
        replace[ins.op1] = trace->ops.size();
        trace->ops.push_back(ins);
      }
    }
    // Emit snaps, including any final snaps.
    while ((cur_snap < arrlen(trace->snaps)) &&
           (trace->snaps[cur_snap].ir == i)) {
      auto &snap = trace->snaps[cur_snap];

      if (cur_snap != 0) {
        snap_s nsnap;
        nsnap.ir = trace->ops.size();
        nsnap.pc = snap.pc;
        nsnap.offset = snap.offset;
        nsnap.exits = 0;
        nsnap.link = -1;
        // Emit loopsnap - all final loop snapshots are carried through loop
        auto &loopsnap = trace->snaps[snap_cut - 1];
        for (auto &entry : loopsnap.slots) {
          if (entry.val < IR_CONST_BIAS) {
            nsnap.slots.push_back({entry.slot, replace[entry.val]});
          } else {
            nsnap.slots.push_back(entry);
          }
        }
        // Emit in-loop snaps.  Merge with
        for (auto &entry : snap.slots) {
          snap_entry_s new_entry;
          if (entry.val < IR_CONST_BIAS) {
            new_entry = {entry.slot, replace[entry.val]};
          } else {
            new_entry = entry;
          }
          bool done = false;
          for (auto &nentry : nsnap.slots) {
            if (nentry.slot == new_entry.slot) {
              nentry.val = new_entry.val;
              done = true;
              break;
            }
          }
          if (!done) {
            nsnap.slots.push_back(new_entry);
          }
        }
        arrput(trace->snaps, nsnap);
      }

      cur_snap++;
    }
    if (i == cut) {
      break;
    }
    auto &ins = trace->ops[i];
    switch (ins.op) {
    case ir_ins_op::ARG:
    case ir_ins_op::SLOAD: {
      assert(regs[ins.op1] >= 0);
      replace[i] = regs[ins.op1];
      printf("Potential phi: %zu %zu\n", i, trace->ops.size());
      phis.push_back(i);
      break;
    }
    case ir_ins_op::GE:
    case ir_ins_op::ADD:
    case ir_ins_op::EQ:
    case ir_ins_op::NE:
    case ir_ins_op::SUB: {
      ir_ins copy = ins;
      if (copy.op1 < IR_CONST_BIAS) {
        copy.op1 = replace[copy.op1];
      }
      if (copy.op2 < IR_CONST_BIAS) {
        copy.op2 = replace[copy.op2];
      }
      replace[i] = trace->ops.size();
      trace->ops.push_back(copy);
      break;
    }
    case ir_ins_op::GGET: {
      ir_ins copy = ins;
      if (copy.op1 < IR_CONST_BIAS) {
        copy.op1 = replace[copy.op1];
      }
      replace[i] = trace->ops.size();
      trace->ops.push_back(copy);
      break;
    }
    default: {
      printf("Can't loop ir type: %s\n", ir_names[(int)ins.op]);
      trace->ops.resize(cut);
      arrsetlen(trace->snaps, snap_cut);
      return;
    }
    }
  }
}
