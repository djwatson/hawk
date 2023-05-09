#pragma once

#include "ir.h"

void assign_registers(trace_s *trace);
void asm_jit(trace_s *trace, snap_s *side);

static constexpr int regcnt = 11;
#define REG_NONE 16
extern const char *reg_names[];

int jit_run(unsigned int tnum, unsigned int **o_pc, long **o_frame,
            long *frame_top);
