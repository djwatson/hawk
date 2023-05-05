#pragma once

#include "ir.h"

void assign_registers(trace_s* trace);
void asm_jit(trace_s* trace);

static constexpr int regcnt = 12;
#define REG_NONE 16
extern const char *reg_names[];
