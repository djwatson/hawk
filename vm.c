// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include <stddef.h>
#include <stdlib.h>

#include "bc.h"
#include "types.h"

typedef struct vm_state {
  bc *pc;
  gc_obj *stack;
  gc_obj *stack_limit;
  gc_obj *stack_orig;
  size_t stack_size;
  bool record;
} vm_state;

gc_obj stack_load(vm_state *st, uint8_t slot) { return st->stack[slot]; }
void stack_save(vm_state *st, uint8_t slot, gc_obj res) {
  st->stack[slot] = res;
}
gc_obj const_load(uint16_t offset);
#define emit_ov_math_op(name, sym, v1, v2) stack_load(nullptr, v1);
#define emit_math_cmp(name, sym, v1, v2) stack_load(nullptr, v1);
#define ensure_type(type, val)
void return_frame(vm_state *st) {
  auto ret = st->stack[st->pc->reg];

  st->pc = to_return_address(st->stack[-1]);
  auto old_pc = st->pc - 1;
  st->stack -= old_pc->reg + 1;
  st->stack[old_pc->reg] = ret;
}
gc_obj sym_load(gc_obj sym);
void prepare_call(gc_obj fun);
void check_arity(gc_obj fun, gc_obj args);
void call_dispatch(gc_obj fun);
void branch_if_false(gc_obj b);
gc_obj closure_get(gc_obj clo, uint8_t slot);
gc_obj return_address(bc *);
void adjust_stack_depth(int depth);
void set_new_pc(bc *func);
void halt();

gc_obj vm(bc *pc) {
  vm_state state = {.pc = pc,
                    .stack = calloc(1024, sizeof(gc_obj)),
                    .stack_size = 1024,
                    .record = false};
  state.stack_limit = state.stack + state.stack_size;
  state.stack_orig = state.stack;
  vm_state *st = &state;

  while (true) {
    switch (pc->op) {
#include "vmgen.c"
    };
  }
}
