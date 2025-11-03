/* Many of the opcodes have repeated parts between the VM and the trace
   recorder.

   Previous tracers have tended to get out of sync, so here is a list
   of opcodes broken down in to hopefully basic parts.  This file is
   then included in both the VM and tracer, hopefully making
   maintenance easier.

   This somewhat resembles how pypy works: One definition for both
   interpreting and tracing.  But we directly emit code to record each
   bytecode, instead of then tracing the python meta-ops.
 */

OP(ADD) {
  auto v1 = stack_load(stack, pc->v1);
  auto v2 = stack_load(stack, pc->v2);
  auto res = emit_ov_math_add(v1, v2);
  stack_save(stack, pc->reg, res);
  pc = next_op(pc);
  return dispatch_next(pc, stack);
}
OP(SUB) {
  auto v1 = stack_load(stack, pc->v1);
  auto v2 = stack_load(stack, pc->v2);
  auto res = emit_ov_math_sub(v1, v2);
  stack_save(stack, pc->reg, res);
  pc = next_op(pc);
  return dispatch_next(pc, stack);
}
OP(CONST) {
  auto c = const_load(pc, pc->v1);
  stack_save(stack, pc->reg, c);
  pc = next_op(pc);
  return dispatch_next(pc, stack);
}
OP(RET) {
  auto frame = return_frame(pc, stack);
  pc = frame.pc;
  stack = frame.stack;
  return dispatch_next(pc, stack);
}
OP(LOOKUP) {
  auto c = const_load(pc, pc->v1);
  ensure_symbol(c);
  auto v1 = sym_load(c);
  stack_save(stack, pc->reg, v1);
  pc = next_op(pc);
  return dispatch_next(pc, stack);
}
OP(FUNC) {
  auto argcnt = pc->data - 1;
  pc = next_op(pc);
  // TODO argcnt check
  return dispatch_next(pc, stack);
}
OP(LT) {
  auto v1 = stack_load(stack, pc->v1);
  auto v2 = stack_load(stack, pc->v2);
  auto res = emit_math_cmp_lt(v1, v2);
  stack_save(stack, pc->reg, res);
  pc = next_op(pc);
  return dispatch_next(pc, stack);
}
OP(IF) {
  auto v = stack_load(stack, pc->reg);
  pc = branch_if_false(pc, v);
  return dispatch_next(pc, stack);
}
OP(CLOSURE_GET) {
  auto clo = stack_load(stack, pc->v1);
  auto slot = stack_load(stack, pc->v2);
  auto res = closure_get(clo, slot);
  stack_save(stack, pc->reg, res);
  pc = next_op(pc);
  return dispatch_next(pc, stack);
}
OP(LCALL) {
  auto func = stack_load(stack, pc->reg);
  auto frame_top = pc->reg;
  stack_save(stack, pc->reg, return_address(pc + 1));
  stack = adjust_stack_depth(stack, frame_top + 1);
  pc = set_new_pc(pc, func);
  return dispatch_next(pc, stack);
}
OP(HALT) {
  return halt(stack);
}
