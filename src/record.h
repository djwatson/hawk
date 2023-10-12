// Copyright 2023 Dave Watson

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "ir.h"

int record(uint32_t *pc, gc_obj *frame, int64_t argcnt);
int record_instr(uint32_t *pc, gc_obj *frame, int64_t argcnt);
void trace_flush(trace_s *ctrace, bool all);
void record_side(trace_s *parent, snap_s *side);
trace_s *trace_cache_get(uint16_t tnum);
void free_trace();
uint8_t get_object_ir_type(int64_t obj);
