#pragma once

#include "ir.h"

typedef struct {
  struct {
    uint8_t reg;
  } arg[2];
} reg_binding;

typedef struct {
  uint16_t reg;
  uint16_t reload_at;
} reload_info;

typedef struct {
  reg_binding *bindings;
  reload_info *reloads;
} regalloc_result;

regalloc_result regalloc(trace *t);
