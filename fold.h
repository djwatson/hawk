#pragma once

#include <stdint.h>

#include "ir.h"

enum : uint8_t {
  FOLD_ARG_ANY = 0xff,
  FOLD_ARG_CONST = 0xfe,
};

typedef enum {
  FOLD_NEXT,
  FOLD_RETRY,
  FOLD_DROP,
  FOLD_CONST,
  FOLD_REF,
} fold_action;

typedef struct {
  fold_action action;
  gc_obj constant;
  slot ref;
} fold_result;

fold_result fold_instr(trace *trace, ir_ins *in);
