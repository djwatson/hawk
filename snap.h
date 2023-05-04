#pragma once

#include "ir.h"

void add_snap(int* regs, int offset, trace_s* trace, uint32_t pc);
void snap_replay(int** regs, snap_s* snap, trace_s* parent, trace_s* trace, long* frame, int*detph);
