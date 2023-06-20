#include <stdint.h>   // for uint32_t
#include <stdio.h>    // for printf
#include <memory>     // for allocator_traits<>::value_type
#include <utility>    // for move
#include <vector>     // for vector
#include "asm_x64.h"  // for REG_NONE
#include "ir.h"       // for snap_s, snap_entry_s, ir_ins, trace_s, IR_CONST...

void add_snap(int *regs, int offset, trace_s *trace, uint32_t *pc) {
  // No need for duplicate snaps.
  if (trace->snaps.size() &&
      trace->snaps[trace->snaps.size() - 1].ir == trace->ops.size() &&
      trace->snaps[trace->snaps.size() - 1].pc == pc) {
    return;
  }
  snap_s snap;
  snap.ir = trace->ops.size();
  snap.pc = pc;
  snap.offset = offset;
  snap.exits = 0;
  snap.link = -1;
  // TODO fix regs size/boj to vec?
  for (int i = 0; i < 257; i++) {
    if (regs[i] != -1) {
      // printf("Record snap entry %i val %i\n", i-1, regs[i]);
      snap_entry_s entry;
      entry.slot = i - 1; // offset by one for callt
      entry.val = regs[i];
      snap.slots.push_back(entry);
    }
  }
  trace->snaps.push_back(std::move(snap));
}

// Replay a snap for a side-trace.
void snap_replay(int **regs, snap_s *snap, trace_s *parent, trace_s *trace,
                 long *frame, int *d) {
  int depth = 0;
  frame -= snap->offset;
  for (auto &slot : snap->slots) {
    if (slot.val & IR_CONST_BIAS) {
      auto c = parent->consts[slot.val - IR_CONST_BIAS];
      if (c & SNAP_FRAME) {
        depth++;
      }
      // Push const in new trace
      auto knum = trace->consts.size();
      trace->consts.push_back(c);
      (*regs)[slot.slot] = knum | IR_CONST_BIAS;
      // printf("Snap replay const %i %i\n", slot.slot, c);
    } else {
      // printf("Snap replay sload %i %i %li ptr %lx op %i\n", slot.slot,
      // slot.val, frame[slot.slot], &frame[slot.val], trace->ops.size());
      //  Emit load
      ir_ins ins;
      ins.reg = REG_NONE;
      ins.op1 = slot.slot;
      ins.op = ir_ins_op::SLOAD;
      // TODO PARENT type, maybe inherit?
      auto type = frame[slot.slot] & 0x7;
      ins.type = type;
      (*regs)[slot.slot] = trace->ops.size();
      trace->ops.push_back(ins);
    }
  }
  *regs = *regs + snap->offset;
  printf("SNAP REPLY DEPTH %i\n", depth);
  *d = depth;
}
