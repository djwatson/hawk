#pragma once

#include <stdint.h>

#include "foreign.h"

typedef struct {
  void *fn;
  uint64_t gpr[6];
  double fpr[6];
  uint64_t ret_u64;
  double ret_f64;
} ffi_call_frame;

void ffi_call_asm(ffi_call_frame *frame);
void ffi_call_foreign(void *fn, void *ret, foreign_type ret_type, void **values,
                      foreign_type *types, uint8_t argcnt);
