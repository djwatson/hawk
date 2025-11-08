// Copyright 2023 Dave Watson

#pragma once

#include <stdint.h>

void profiler_start();
void profiler_stop();
void profiler_set_in_jit(bool active);
void profiler_set_in_gc(bool active);
void profile_add_frame(uint32_t *ptr);
void profile_pop_frame();
void profile_pop_all_frames();
void profile_set_pc(uint32_t *pc);
