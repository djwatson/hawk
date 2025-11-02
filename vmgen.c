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
  auto v1 = stack_load(st, st->pc->v1);
  auto v2 = stack_load(st, st->pc->v2);
  auto res = emit_ov_math_op(add, +, v1, v2);
  stack_save(st, st->pc->reg, res);
  next_op(st);
  next(st);
}
OP(SUB) {
  auto v1 = stack_load(st, st->pc->v1);
  auto v2 = stack_load(st, st->pc->v2);
  auto res = emit_ov_math_op(sub, -, v1, v2);
  stack_save(st, st->pc->reg, res);
  next_op(st);
  next(st);
}
OP(CONST) {
  auto c = const_load(st, st->pc->v1);
  stack_save(st, st->pc->reg, c);
  next_op(st);
  next(st);
}
OP(RET) {
  return_frame(st);
  next(st);
}
OP(LOOKUP) {
  auto c = const_load(st, st->pc->v1);
  ensure_type(symbol, c);
  auto v1 = sym_load(c);
  stack_save(st, st->pc->reg, v1);
  next_op(st);
  next(st);
}
OP(FUNC) {
  auto argcnt = st->pc->data - 1;
  next_op(st);
  // TODO argcnt check
  next(st);
}
OP(LT) {
  auto v1 = stack_load(st, st->pc->v1);
  auto v2 = stack_load(st, st->pc->v2);
  auto res = emit_math_cmp(lt, <, v1, v2);
  stack_save(st, st->pc->reg, res);
  next_op(st);
  next(st);
}
OP(IF) {
  auto v = stack_load(st, st->pc->reg);
  branch_if_false(st, v);
  next(st);
}
OP(CLOSURE_GET) {
  auto clo = stack_load(st, st->pc->v1);
  auto slot = stack_load(st, st->pc->v2);
  auto res = closure_get(clo, slot);
  stack_save(st, st->pc->reg, res);
  next_op(st);
  next(st);
}
OP(LCALL) {
  auto func = stack_load(st, st->pc->reg);
  auto frame_top = st->pc->reg;
  stack_save(st, st->pc->reg, return_address(st->pc + 1));
  adjust_stack_depth(st, frame_top + 1);
  set_new_pc(st, func);
  next(st);
}
OP(HALT) {
  halt();
  next(st);
}
