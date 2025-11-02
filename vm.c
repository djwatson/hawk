// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

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
gc_obj const_load(vm_state *st, uint16_t offset) {
  return *(gc_obj*)(st->pc - st->pc->data);
}
// TODO typecheck
#define emit_ov_math_op(name, sym, v1, v2) tag_fixnum(to_fixnum(v1) sym to_fixnum(v2));
#define emit_math_cmp(name, sym, v1, v2) to_fixnum(v1) < to_fixnum(v2) ? TRUE_REP : FALSE_REP
#define ensure_type(type, val)
void return_frame(vm_state *st) {
  auto ret = st->stack[st->pc->reg];

  st->pc = to_return_address(st->stack[-1]);
  auto old_pc = st->pc - 1;
  st->stack -= old_pc->reg + 1;
  st->stack[old_pc->reg] = ret;
}
gc_obj sym_load(gc_obj sym) {
  return to_symbol(sym)->val;
}
void prepare_call(gc_obj fun) {
  // TODO nothing?
}
void check_arity(gc_obj fun, gc_obj args) {
  // TODO nothing for now
  
}
void call_dispatch(vm_state* st, uint8_t frame_top, gc_obj fun) {
  st->stack[frame_top] = tag_return_address(st->pc + 1);
  st->stack += frame_top + 1;
  auto func = to_func(fun);
  st->pc = (bc*)(func->data + (func->const_cnt * sizeof(gc_obj)));
  // TODO something?
}
void branch_if_false(vm_state *st, gc_obj b) {
  if (b.value == FALSE_REP.value) {
    st->pc += st->pc->data;
  } else {
    st->pc++;
  }
}
gc_obj closure_get(gc_obj clo, gc_obj slot) {
  return to_closure(clo)->v[to_fixnum(slot)];
}
gc_obj return_address(bc * ra) {
  return tag_return_address(ra);
}
void adjust_stack_depth(vm_state* st, int depth) {
  // TODO check stack depth?
  st->stack += depth;
}
void set_new_pc(vm_state* st, gc_obj func) {
  auto bfunc = to_func(func);
  st->pc = (bc*)(&bfunc->data[bfunc->const_cnt * sizeof(gc_obj)]);
}
#define halt() return st->stack[0]
void next_op(vm_state* st) {
  st->pc++;
}

gc_obj vm(bc *pc) {
  vm_state state = {.pc = pc,
                    .stack = calloc(1024, sizeof(gc_obj)),
                    .stack_size = 1024,
                    .record = false};
  state.stack_limit = state.stack + state.stack_size;
  state.stack_orig = state.stack;
  vm_state *st = &state;

  while (true) {
    switch (st->pc->op) {
#include "vmgen.c"
    };
  }
}
