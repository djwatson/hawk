// Copyright 2023 Dave Watson

#pragma once

#include <stdint.h>

#include "ir.h"

void add_snap(const uint16_t *regs, int32_t offset, trace_s *trace, uint32_t *pc,
              uint32_t depth, uint32_t stack_top);
uint32_t snap_replay(uint16_t **regs, snap_s *snap, trace_s *parent, trace_s *trace,
                     int *depth);
void free_snap(snap_s *snap);
