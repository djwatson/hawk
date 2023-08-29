#pragma once

#include "ir.h"

void add_snap(const int *regs, int offset, trace_s *trace, uint32_t *pc,
              uint32_t depth);
void snap_replay(int **regs, snap_s *snap, trace_s *parent, trace_s *trace,
                 const long *frame, int *detph);
