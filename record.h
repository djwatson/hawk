#pragma once

#include "ir.h"

#ifdef __cplusplus
extern "C" {
#endif
int record(unsigned int *pc, long *frame, long argcnt);
int record_instr(unsigned int *pc, long *frame, long argcnt);
void record_side(trace_s *parent, snap_s *side);
trace_s *trace_cache_get(unsigned int tnum);
void free_trace();
#ifdef __cplusplus
}
#endif
