// Copyright 2023 Dave Watson

#pragma once

#include <stdint.h>

void profiler_start();
void profiler_stop();
void profiler_set_in_jit(bool active);
void profiler_set_in_gc(bool active);
