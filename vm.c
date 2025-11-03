// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

#include "bc.h"
#include "types.h"
#include "hawk.h"

#define OP(code) gc_obj impl_##code(bc *pc, gc_obj *stack) 

gc_obj stack_load(gc_obj* stack, uint8_t slot) { return stack[slot]; }
void stack_save(gc_obj* stack, uint8_t slot, gc_obj res) {
  stack[slot] = res;
}
gc_obj const_load(bc *pc, uint16_t offset) {
  return *(gc_obj*)(pc - pc->data);
}
// TODO typecheck
#define emit_ov_math_op(name, sym, v1, v2) tag_fixnum(to_fixnum(v1) sym to_fixnum(v2));
#define emit_math_cmp(name, sym, v1, v2) to_fixnum(v1) < to_fixnum(v2) ? TRUE_REP : FALSE_REP
#define ensure_type(type, val)
#define return_frame(pc, stack)                                                \
  auto ret = stack[pc->reg];                                                   \
  pc = to_return_address(stack[-1]);                                           \
  auto old_pc = pc - 1;                                                        \
  stack -= old_pc->reg + 1;                                                    \
  stack[old_pc->reg] = ret;

gc_obj sym_load(gc_obj sym) {
  return to_symbol(sym)->val;
}
void prepare_call(gc_obj fun) {
  // TODO nothing?
}
void check_arity(gc_obj fun, gc_obj args) {
  // TODO nothing for now
  
}
bc* branch_if_false(bc* pc, gc_obj b) {
  if (b.value == FALSE_REP.value) {
    return pc + pc->data;
  } else {
    return pc+1;
  }
}
gc_obj closure_get(gc_obj clo, gc_obj slot) {
  return to_closure(clo)->v[to_fixnum(slot)];
}
gc_obj return_address(bc * ra) {
  return tag_return_address(ra);
}
gc_obj* adjust_stack_depth(gc_obj * stack, int depth) {
  // TODO check stack depth?
  return stack += depth;
}
bc* set_new_pc(bc* pc, gc_obj func) {
  auto bfunc = to_func(func);
  return (bc*)(&bfunc->data[bfunc->const_cnt * sizeof(gc_obj)]);
}
#define halt() return stack[0]
#define next_op(pc) pc++;


typedef gc_obj (*op_func)(bc* pc, gc_obj* stack);
static op_func impls[OP_INS_MAX];
#define next() MUSTTAIL return impls[pc->op](pc, stack);

  #include "vmgen.c"

gc_obj vm(bc *pc) {
#define X(name) impls[OP_##name] = impl_##name;
OPS
#undef X
  gc_obj* stack = calloc(1024, sizeof(gc_obj));

  // TODO
 return impls[pc->op](pc, stack);
}
