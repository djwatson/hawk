// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include "bc.h"
#include "types.h"
#include "hawk.h"

#define OP(code) PRESERVE_NONE gc_obj impl_##code(bc *pc, gc_obj *stack)

typedef gc_obj PRESERVE_NONE (*op_func)(bc *pc, gc_obj *stack);

typedef struct {
  bc *pc;
  gc_obj *stack;
} frame_state;

static op_func impls[OP_INS_MAX];

static inline gc_obj stack_load(gc_obj* stack, uint8_t slot) { return stack[slot]; }
static inline void stack_save(gc_obj* stack, uint8_t slot, gc_obj res) {
  stack[slot] = res;
}
static inline gc_obj const_load(bc *pc, uint16_t offset) {
  return *(gc_obj*)(pc - pc->data);
}
static inline gc_obj emit_ov_math_add(gc_obj v1, gc_obj v2) {
  return tag_fixnum(to_fixnum(v1) + to_fixnum(v2));
}
static inline gc_obj emit_ov_math_sub(gc_obj v1, gc_obj v2) {
  return tag_fixnum(to_fixnum(v1) - to_fixnum(v2));
}
static inline gc_obj emit_math_cmp_lt(gc_obj v1, gc_obj v2) {
  return to_fixnum(v1) < to_fixnum(v2) ? TRUE_REP : FALSE_REP;
}
static inline void ensure_symbol(gc_obj val) {
  (void)val;
}
static inline frame_state return_frame(bc *pc, gc_obj *stack) {
  auto ret = stack[pc->reg];
  auto new_pc = to_return_address(stack[-1]);
  auto old_pc = new_pc - 1;
  auto new_stack = stack - old_pc->reg - 1;
  new_stack[old_pc->reg] = ret;
  return (frame_state){.pc = new_pc, .stack = new_stack};
}
static inline bc* next_op(bc *pc) {
  return pc + 1;
}
static inline gc_obj halt(gc_obj *stack) {
  return stack[0];
}

static inline gc_obj sym_load(gc_obj sym) {
  return to_symbol(sym)->val;
}
static inline void prepare_call(gc_obj fun) {
  // TODO nothing?
}
static inline void check_arity(gc_obj fun, gc_obj args) {
  // TODO nothing for now
  
}
static inline bc* branch_if_false(bc* pc, gc_obj b) {
  if (b.value == FALSE_REP.value) {
    return pc + pc->data;
  } else {
    return pc+1;
  }
}
static inline gc_obj closure_get(gc_obj clo, gc_obj slot) {
  return to_closure(clo)->v[to_fixnum(slot)];
}
static inline gc_obj return_address(bc * ra) {
  return tag_return_address(ra);
}
static inline gc_obj* adjust_stack_depth(gc_obj * stack, int depth) {
  // TODO check stack depth?
  return stack += depth;
}
static inline bc* set_new_pc(bc* pc, gc_obj func) {
  auto bfunc = to_func(func);
  return (bc*)(&bfunc->data[bfunc->const_cnt * sizeof(gc_obj)]);
}
#define dispatch_next(pc, stack) \
  MUSTTAIL return impls[pc->op](pc, stack);


  #include "vmgen.c"

gc_obj vm(bc *pc) {
#define X(name) impls[OP_##name] = impl_##name;
OPS
#undef X
  gc_obj* stack = calloc(1024, sizeof(gc_obj));

 return impls[pc->op](pc, stack);
}
