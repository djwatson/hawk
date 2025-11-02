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

case OP_ADD: {
  auto v1 = stack_load(st, st->pc->v1);
  auto v2 = stack_load(st, st->pc->v2);
  auto res = emit_ov_math_op(add, +, v1, v2);
  stack_save(st, st->pc->reg, res);
  next_op(st);
  break;
}
case OP_SUB: {
  auto v1 = stack_load(st, st->pc->v1);
  auto v2 = stack_load(st, st->pc->v2);
  auto res = emit_ov_math_op(sub, -, v1, v2);
  stack_save(st, st->pc->reg, res);
  next_op(st);
  break;
}
case OP_CONST: {
  auto c = const_load(st, st->pc->v1);
  stack_save(st, st->pc->reg, c);
  next_op(st);
  break;
}
case OP_RET: {
  return_frame(st);
  break;
}
case OP_LOOKUP: {
  auto c = const_load(st, st->pc->v1);
  ensure_type(symbol, c);
  auto v1 = sym_load(c);
  stack_save(st, st->pc->reg, v1);
  next_op(st);
  break;
}
case OP_FUNC: {
  auto argcnt = st->pc->data - 1;
  next_op(st);
  // TODO argcnt check
  break;
}
case OP_LT: {
  auto v1 = stack_load(st, st->pc->v1);
  auto v2 = stack_load(st, st->pc->v2);
  auto res = emit_math_cmp(lt, <, v1, v2);
  stack_save(st, st->pc->reg, res);
  next_op(st);
  break;
}
case OP_IF: {
  auto v = stack_load(st, st->pc->reg);
  branch_if_false(st, v);
  break;
}
case OP_CLOSURE_GET: {
  auto clo = stack_load(st, st->pc->v1);
  auto slot = stack_load(st, st->pc->v2);
  auto res = closure_get(clo, slot);
  stack_save(st, st->pc->reg, res);
  next_op(st);
  break;
}
case OP_LCALL: {
  auto func = stack_load(st, st->pc->reg);
  auto frame_top = st->pc->reg;
  stack_save(st, st->pc->reg, return_address(st->pc + 1));
  adjust_stack_depth(st, frame_top + 1);
  set_new_pc(st, func);
  break;
}
case OP_HALT: {
  halt();
  break;
}
