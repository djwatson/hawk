#include "ffi.h"

void ffi_call_foreign(void *fn, void *ret, foreign_type ret_type, void **values,
                      foreign_type *types, uint8_t argcnt) {
  ffi_call_frame frame = {0};
  frame.fn = fn;
  uint8_t ngpr = 0, nfpr = 0;

  for (uint8_t i = 0; i < argcnt; i++) {
    if (types[i] == FOREIGN_TYPE_DOUBLE) {
      frame.fpr[nfpr++] = *(double *)values[i];
    } else {
      frame.gpr[ngpr++] = *(uint64_t *)values[i];
    }
  }

  ffi_call_asm(&frame);

  if (ret_type == FOREIGN_TYPE_DOUBLE) {
    *(double *)ret = frame.ret_f64;
  } else {
    *(uint64_t *)ret = frame.ret_u64;
  }
}
