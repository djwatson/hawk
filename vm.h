#pragma once

#include "asm.h"
#include "bc.h"
#include "hawk.h"
#include "record.h"
#include "types.h"

struct vm_state;

typedef gc_obj PRESERVE_NONE (*op_func)(bc instr, bc *pc, gc_obj *stack,
                                        struct vm_state *state, void *op_table,
                                        uint64_t argcnt);

enum { VM_HOTMAP_SZ = 64 };
enum { STACK_GUARD_SLOTS = 256 };

typedef struct vm_state {
  uint8_t hotmap[VM_HOTMAP_SZ];
  uint16_t max_trace;
  gc_obj *stack_top;
  gc_obj *stack_bottom;
  gc_obj *stack_limit;
  op_func record_impls[OP_INS_MAX];
  op_func impls[OP_INS_MAX];
  record_state record;
  emit_state emit;
} vm_state;

gc_obj vm(bcfunc *func);
gc_obj *expand_stack(vm_state *state, gc_obj *stack);
void vm_trace_reset(void);
