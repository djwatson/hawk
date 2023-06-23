#pragma once

struct snap_s;
struct trace_s;

int record(unsigned int *pc, long *frame, long argcnt);
int record_instr(unsigned int *pc, long *frame, long argcnt);
void record_side(trace_s *parent, snap_s *side);
trace_s *trace_cache_get(unsigned int tnum);
void free_trace();
