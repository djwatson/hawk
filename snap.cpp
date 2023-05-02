#include <stdio.h>

#include "snap.h"

void add_snap(int* regs, int offset, trace_s* trace, uint32_t pc) {
  // No need for duplicate snaps.
  if (trace->snaps.size() &&
      trace->snaps[trace->snaps.size()-1].ir == trace->ops.size()) {
    return;
  }
  snap_s snap;
  snap.ir = trace->ops.size();
  snap.pc = pc;
  snap.offset = offset;
  snap.exits = 0;
  // TODO fix regs size/boj to vec?
  for(int i = 0; i < 257; i++) {
    if (regs[i] != -1) {
      snap_entry_s entry;
      entry.slot = i - 1; // offset by one for callt
      entry.val = regs[i];
      snap.slots.push_back(entry);
    }
  }
  trace->snaps.push_back(std::move(snap));
}
