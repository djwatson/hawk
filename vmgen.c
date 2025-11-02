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
  auto v1 = stack_load(pc->v1);
  auto v2 = stack_load(pc->v2);
  auto res = emit_ov_math_op(add, +, pc->v1, pc->v2);
  stack_save(pc->reg, res);
  break;
}
case OP_SUB: {
  auto v1 = stack_load(pc->v1);
  auto v2 = stack_load(pc->v2);
  auto res = emit_ov_math_op(sub, -, pc->v1, pc->v2);
  stack_save(pc->reg, res);
  break;
}
case OP_CONST: {
  auto c = const_load(pc->v1);
  stack_save(pc->reg, c);
  break;
}
case OP_RET: {
  return_frame(pc);
  break;
}
case OP_LOOKUP: {
  auto c = const_load(pc->v1);
  ensure_type(symbol, c);
  auto v1 = sym_load(c);
  stack_save(pc->reg, v1);
  break;
}
case OP_FUNC: {
  auto fun = stack_load(pc->v1);
  auto args = stack_load(pc->v2);
  ensure_type(closure, fun);
  prepare_call(fun);
  check_arity(fun, args);
  call_dispatch(fun);
  break;
}
case OP_LT: {
  auto v1 = stack_load(pc->v1);
  auto v2 = stack_load(pc->v2);
  auto res = emit_math_cmp(lt, <, pc->v1, pc->v2);
  stack_save(pc->reg, res);
  break;
}
case OP_IF: {
  auto v = stack_load(pc->v1);
  branch_if_false(v);
  break;
}
case OP_CLOSURE_GET: {
  auto clo = stack_load(pc->v1);
  auto slot = pc->v2;
  auto res = closure_get(clo, slot);
  stack_save(pc->reg, res);
  break;
}
case OP_LCALL: {
  auto func = (bc *)stack_load(pc->reg).ptr;
  auto frame_top = pc->reg;
  stack_save(pc->reg, return_address(func + 1));
  adjust_stack_depth(func->reg + 1);
  set_new_pc(func);
  break;
}
case OP_HALT: {
  halt();
  break;
}
