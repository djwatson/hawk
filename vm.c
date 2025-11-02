// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include "bc.h"
#include "types.h"

gc_obj stack_load(uint8_t slot);
gc_obj const_load(uint16_t offset);
#define emit_ov_math_op(name, sym, v1, v2) stack_load(v1);
#define emit_math_cmp(name, sym, v1, v2) stack_load(v1);
#define ensure_type(type, val)
void return_frame(void *pc);
gc_obj sym_load(gc_obj sym);
void prepare_call(gc_obj fun);
void check_arity(gc_obj fun, gc_obj args);
void call_dispatch(gc_obj fun);
void stack_save(uint8_t slot, gc_obj res);
void branch_if_false(gc_obj b);
gc_obj closure_get(gc_obj clo, uint8_t slot);
gc_obj return_address(bc *);
void adjust_stack_depth(int depth);
void set_new_pc(bc *func);
void halt();

int vm(bc *pc) {
  while (true) {
    switch (pc->op) {
#include "vmgen.c"
    };
  }
}
