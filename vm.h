#pragma once

#include "hawk.h"
#include "bc.h"
#include "types.h"

struct vm_state;

typedef gc_obj PRESERVE_NONE (*op_func)(bc *pc, gc_obj *stack,
                                        struct vm_state *state,
                                        void *op_table, uint8_t argcnt);

enum { VM_HOTMAP_SZ = 64 };

typedef struct vm_state {
  uint8_t hotmap[VM_HOTMAP_SZ];
  uint8_t max_trace;
  op_func record_impls[OP_INS_MAX];
  op_func impls[OP_INS_MAX];
} vm_state;

gc_obj vm(bc *pc);
