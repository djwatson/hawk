#pragma once

#include "ir.h"

int record(unsigned int *pc, long *frame);
int record_instr(unsigned int *pc, long *frame);
trace_s* trace_cache_get(unsigned int tnum);
