// Copyright 2023 Dave Watson

#pragma once

#include <stdint.h>

struct vm_state;
void profiler_start(struct vm_state *state);
void profiler_stop(struct vm_state *state);
void profiler_set_in_jit(bool active);
void profiler_set_in_gc(bool active);
