#pragma once

#include <stdint.h>

#include "ir.h"

enum : uint8_t {
  FOLD_ARG_ANY = 0xff,
  FOLD_ARG_CONST = 0xfe,
};

void fold_instr(trace *trace, ir_ins *in);
