#include "snap.h"
#include "asm_x64.h" // for REG_NONE
#include "ir.h"      // for snap_s, snap_entry_s, ir_ins, trace_s, IR_CONST...
#include "third-party/stb_ds.h"
#include <stdint.h> // for uint32_t
#include <stdio.h>  // for printf
#define auto __auto_type

void add_snap(const int *regs, int offset, trace_s *trace, uint32_t *pc,
              uint32_t depth) {
  // No need for duplicate snaps.
  if ((arrlen(trace->snaps) != 0) &&
      trace->snaps[arrlen(trace->snaps) - 1].ir == arrlen(trace->ops) &&
      trace->snaps[arrlen(trace->snaps) - 1].pc == pc) {
    return;
  }
  snap_s snap;
  snap.ir = arrlen(trace->ops);
  snap.pc = pc;
  snap.offset = offset;
  snap.exits = 0;
  snap.link = -1;
  snap.slots = NULL;
  snap.depth = depth;
  snap.argcnt = 1;
  // TODO fix regs size/boj to vec?
  for (int16_t i = 0; i < 257; i++) {
    if (regs[i] != -1) {
      // printf("Record snap entry %i val %i\n", i-1, regs[i]);
      snap_entry_s entry;
      entry.slot = (int16_t)(i - 1); // offset by one for callt
      entry.val = regs[i];
      arrput(snap.slots, entry);
    }
  }
  if (arrlen(trace->snaps) > 0 && trace->snaps[arrlen(trace->snaps)-1].ir == snap.ir) {
    snap_s sn = arrpop(trace->snaps);
    free_snap(&sn);
  }
  arrput(trace->snaps, snap);
}

// Replay a snap for a side-trace.
void snap_replay(int **regs, snap_s *snap, trace_s *parent, trace_s *trace,
                 const long *frame, int *d) {
  frame -= snap->offset;
  for (uint64_t i = 0; i < arrlen(snap->slots); i++) {
    auto slot = &snap->slots[i];
    if ((slot->val & IR_CONST_BIAS) != 0) {
      auto c = parent->consts[slot->val - IR_CONST_BIAS];
      // Push const in new trace
      int knum = arrlen(trace->consts);
      arrput(trace->consts, c);
      (*regs)[slot->slot] = knum | IR_CONST_BIAS;
      // printf("Snap replay const %i %i\n", slot->slot, c);
    } else {
      // printf("Snap replay sload %i %i %li ptr %lx op %i\n", slot->slot,
      // slot->val, frame[slot->slot], &frame[slot->val], arrlen(trace->ops));
      //  Emit load
      ir_ins ins;
      ins.reg = REG_NONE;
      ins.op1 = slot->slot;
      ins.op = IR_SLOAD;
      ins.slot = SLOT_NONE;
      // TODO PARENT type, maybe inherit?
      auto type = frame[slot->slot] & 0x7;
      ins.type = type;
      (*regs)[slot->slot] = arrlen(trace->ops);
      arrput(trace->ops, ins);
    }
  }
  *regs = *regs + snap->offset;
  *d = snap->depth;
}

void free_snap(snap_s* snap) {
  arrfree(snap->slots);
}
