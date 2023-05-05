#pragma once

#include "ir.h"

void assign_registers(trace_s* trace);

static constexpr int regcnt = 16;
#define REG_NONE 16
extern const char *reg_names[];
