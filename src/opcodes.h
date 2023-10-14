#pragma once

#include "opcodes-gen.h"

extern const char* ins_names[];
enum {
#define X(name,str) name,
  BYTECODE_INSTRUCTIONS
#undef X
  INS_MAX
};
