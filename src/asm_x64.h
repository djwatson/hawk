// Copyright 2023 Dave Watson

#pragma once

#include <stdint.h>

#include "ir.h"
#include "types.h"

void assign_registers(trace_s *trace);
void asm_jit(trace_s *trace, snap_s *side, trace_s *parent);

#define regcnt 16
#define REG_NONE 16
#define SLOT_NONE 0
extern const char *reg_names[];

int jit_run(trace_s *trace, unsigned int **o_pc, gc_obj **o_frame,
            int64_t *argcnt);
