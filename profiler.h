// Copyright 2023 Dave Watson

#pragma once

#include <stdint.h>

void profiler_start(void);
void profiler_stop(void);
void profiler_set_in_jit(bool active);
void profiler_set_in_gc(bool active);
uint64_t profiler_gc_enter(void);
void profiler_gc_exit(uint64_t start_total_samples, uint64_t duration_ns);
void profiler_register_jit_symbol(void *start, void *end, const char *name);
