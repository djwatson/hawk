#pragma once

#include "ir.h"

int record(unsigned int *pc, long *frame);
int record_instr(unsigned int *pc, long *frame);
void record_side(trace_s *parent, snap_s *side);
trace_s *trace_cache_get(unsigned int tnum);
