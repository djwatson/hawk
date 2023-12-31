// Copyright 2023 Dave Watson

#include "snap.h"

#include <stddef.h>
#include <stdint.h> // for uint32_t
#include <stdio.h>  // for printf

#include "asm_x64.h" // for REG_NONE
#include "defs.h"
#include "ir.h" // for snap_s, snap_entry_s, ir_ins, trace_s, IR_CONST...
#include "third-party/stb_ds.h"

void add_snap(const uint16_t *regs, ptrdiff_t off, trace_s *trace, uint32_t *pc,
              uint32_t depth, uint32_t stack_top) {
  // TODO size check offset
  int32_t offset = (int32_t)off; // NOLINT
  snap_s snap;
  snap.ir = arrlen(trace->ops);
  snap.pc = pc;
  snap.offset = offset;
  snap.exits = 0;
  snap.slots = NULL;
  snap.depth = depth;
  snap.argcnt = 1;
  snap.patchpoint = 0;
  auto top = offset + stack_top + 1 /* offset */;
  for (int32_t i = 0; i < top; i++) {
    if (regs[i] != REGS_NONE) {
      snap_entry_s entry;
      entry.slot = (int16_t)(i - 1); // offset by one for callt
      entry.val = regs[i];
      arrput(snap.slots, entry);
    }
  }
  // No need for duplicate snaps.
  if (arrlen(trace->snaps) > 0 &&
      trace->snaps[arrlen(trace->snaps) - 1].ir == snap.ir) {
    snap_s sn = arrpop(trace->snaps);
    free_snap(&sn);
  }
  arrput(trace->snaps, snap);
}

// Replay a snap for a side-trace.
uint32_t snap_replay(uint16_t **regs, snap_s *snap, trace_s *parent,
                     trace_s *trace, int *d) {
  for (uint64_t i = 0; i < arrlen(snap->slots); i++) {
    auto slot = &snap->slots[i];
    if (ir_is_const(slot->val)) {
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
      ins.op2 = SLOAD_PARENT;
      ins.slot = SLOT_NONE;
      // TODO(djwatson) PARENT type, maybe inherit?
      auto type = parent->ops[slot->val].type & ~IR_INS_TYPE_GUARD;
      ins.type = type;
      (*regs)[slot->slot] = arrlen(trace->ops);
      arrput(trace->ops, ins);
    }
  }
  *regs = *regs + snap->offset;
  *d = snap->depth;
  if (!arrlen(snap->slots)) {
    return 0;
  }
  return snap->slots[arrlen(snap->slots) - 1].slot + 1 /* top is one above */;
}

void free_snap(snap_s *snap) { arrfree(snap->slots); }
