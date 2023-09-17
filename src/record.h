#pragma once

#include <stdint.h>
#include "ir.h"

int record(unsigned int *pc, long *frame, long argcnt);
int record_instr(unsigned int *pc, long *frame, long argcnt);
void record_side(trace_s *parent, snap_s *side);
trace_s *trace_cache_get(uint16_t tnum);
void free_trace();
uint8_t get_object_ir_type(int64_t obj) ;
