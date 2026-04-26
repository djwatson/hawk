// Copyright 2023 Dave Watson

#pragma once

#include <stdint.h>

void profiler_start(void);
void profiler_reset(void);
void profiler_stop(void);
void profiler_set_in_jit(bool active);
void profiler_set_in_gc(bool active);
void profiler_register_jit_symbol(void *start, void *end, const char *name);
