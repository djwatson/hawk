#include "snap.h"

void add_snap(int* regs, trace_s* trace, uint32_t pc) {
  // No need for duplicate snaps.
  if (trace->snaps.size() &&
      trace->snaps[trace->snaps.size()-1].ir == trace->ops.size()) {
    return;
  }
  snap_s snap;
  snap.ir = trace->ops.size();
  snap.pc = pc;
  // TODO fix regs size/boj to vec?
  for(int i = 0; i < 256; i++) {
    if (regs[i] != -1) {
      snap_entry_s entry;
      entry.slot = i;
      entry.val = regs[i];
      snap.slots.push_back(entry);
    }
  }
  trace->snaps.push_back(std::move(snap));
}
