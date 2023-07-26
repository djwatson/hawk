#pragma once

#include "ir.h"

#ifdef __cplusplus
extern "C" {
#endif
void add_snap(const int *regs, int offset, trace_s *trace, uint32_t *pc);
void snap_replay(int **regs, snap_s *snap, trace_s *parent, trace_s *trace,
                 const long *frame, int *detph);
#ifdef __cplusplus
}
#endif
