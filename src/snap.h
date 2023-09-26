#pragma once

#include <stdint.h>

#include "ir.h"

void add_snap(const int *regs, int offset, trace_s *trace, uint32_t *pc,
              uint32_t depth, int32_t stack_top);
uint32_t snap_replay(int **regs, snap_s *snap, trace_s *parent, trace_s *trace,
                 int *detph);
void free_snap(snap_s* snap);
