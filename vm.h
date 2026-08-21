#pragma once

#include "asm.h"
#include "bc.h"
#include "hawk.h"
#include "record.h"
#include <setjmp.h>
#include "types.h"

struct vm_state;

typedef struct {
  gc_obj value;
  gc_obj *stack;
} vm_callcc_result;

typedef gc_obj PRESERVE_NONE (*op_func)(bc instr, bc *pc, gc_obj *stack,
                                        struct vm_state *state, void *op_table,
                                        uint64_t argcnt);

enum { VM_HOTMAP_SZ = 1024 };
enum { STACK_GUARD_SLOTS = 256 };

typedef struct vm_state {
  uint8_t hotmap[VM_HOTMAP_SZ];
  uint16_t max_trace;
  gc_obj *stack_top;
  gc_obj *stack_end;
  gc_obj *stack_bottom;
  gc_obj *stack_limit;
  op_func record_impls[OP_INS_MAX];
  op_func impls[OP_INS_MAX];
  record_state record;
  emit_state emit;
  jmp_buf jit_oom_jmp;
  bc *jit_oom_pc;
  gc_obj *jit_oom_stack;
  uint64_t jit_oom_argcnt;
} vm_state;

gc_obj vm(gc_obj clo, gc_obj arg1, gc_obj arg2);
gc_obj vm_memq(gc_obj obj, gc_obj list);
gc_obj vm_memv(gc_obj obj, gc_obj list);
gc_obj *expand_stack(vm_state *state, gc_obj *stack);
vm_callcc_result vm_callcc_slow(vm_state *state, gc_obj *stack,
                                gc_obj callcc_arg, gc_obj winders,
                                gc_obj reroot_proc);
gc_obj vm_callcc_resume_func_obj(void);
gc_obj vm_callcc_resume_stub_ra(void);
bool vm_is_callcc_resume_stub_pc(bc *pc);
gc_obj *vm_callcc_resume_slow(vm_state *state, gc_obj captured);
void vm_trace_reset(void);
bool vm_jit_enabled(void);
bool vm_jit_set_enabled(bool enabled);
