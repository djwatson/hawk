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

#ifndef VMGEN_TRACE_OP
#define VMGEN_TRACE_OP(pc, code) ((void)0)
#endif

#ifndef OP_BEGIN
#define OP_BEGIN(code)                                                         \
  OP(code) {                                                                   \
    VMGEN_TRACE_OP(pc, code);
#define END }
#endif

OP_BEGIN(ADD) {
  auto v1 = stack_load(state, stack, pc->v1, true);
  auto v2 = stack_load(state, stack, pc->v2, true);
  auto res = emit_ov_math_add(state, v1, v2);
  stack_save(state, stack, pc->reg, res);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(SUB) {
  auto v1 = stack_load(state, stack, pc->v1, true);
  auto v2 = stack_load(state, stack, pc->v2, true);
  auto res = emit_ov_math_sub(state, v1, v2);
  stack_save(state, stack, pc->reg, res);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(CONST) {
  auto c = const_load(state, pc, pc->data);
  stack_save(state, stack, pc->reg, c);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(KSHORT) {
  auto c = constify_data(state, pc->data);
  stack_save(state, stack, pc->reg, c);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(MOV) {
  auto c = stack_load(state, stack, pc->data, false);
  stack_save(state, stack, pc->reg, c);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(RET) {
  /* auto res = check_record_start(pc, stack, state, op_table); */
  /* if (res != op_table) { */
  /*   op_table = res; */
  /*   dispatch_next(pc, stack); */
  /* } */
  auto frame = return_frame(state, pc, stack, op_table);
  pc = frame.pc;
  stack = frame.stack;
  op_table = frame.ops;
  dispatch_next(pc, stack);
}
END OP_BEGIN(LOOKUP) {
  auto c = const_load(state, pc, pc->data);
  // No need to check if c is a symbol, the compiler guarantees it
  auto v1 = sym_load(state, c);
  stack_save(state, stack, pc->reg, v1);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(DEFINE) {
  auto c = const_load(state, pc, pc->data);
  auto val = stack_load(state, stack, pc->reg, false);
  sym_store(state, c, val);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(WRITE) {
  auto val = stack_load(state, stack, pc->v1, false);
  obj_write(state, val);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(FUNC) {
  // TODO argcnt check
  auto expect_argcnt = pc->reg;
  check_arity(expect_argcnt, argcnt);

  // TODO merge with arity check?
  check_expand_stack(state, &stack);
  op_table = check_record_start(pc, stack, state, op_table);

  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(JFUNC) {
  // TODO argcnt check - no, will be put in trace itself!
  auto f = pc->data;
  op_table = jit_func(&pc, &stack, state, op_table);

  dispatch_next(pc, stack);
}
END OP_BEGIN(JLT) {
  auto v1 = stack_load(state, stack, pc->v1, true);
  auto v2 = stack_load(state, stack, pc->v2, true);
  auto res = emit_math_cmp_lt(state, v1, v2);
  pc = branch_if_op(state, pc, stack, res);
  dispatch_next(pc, stack);
}
END OP_BEGIN(JEQV) {
  auto v1 = stack_load(state, stack, pc->v1, true);
  auto v2 = stack_load(state, stack, pc->v2, true);
  auto res = emit_math_cmp_eq(state, v1, v2);
  pc = branch_if_op(state, pc, stack, res);
  dispatch_next(pc, stack);
}
END OP_BEGIN(IF) {
  auto v = stack_load(state, stack, pc->data, false);
  pc = branch_if_op(state, pc, stack, v);
  dispatch_next(pc, stack);
}
END OP_BEGIN(JMP) {
  pc += pc->data;
  dispatch_next(pc, stack);
}
END OP_BEGIN(CLOSURE_GET) {
  auto clo = stack_load(state, stack, pc->v1, false);
  fail_if_not_closure(clo);
  auto slot = pc->v2;
  auto res = closure_get(state, clo, slot);
  stack_save(state, stack, pc->reg, res);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(LCALL) {
  argcnt = pc->data - 1;
  auto func = stack_load(state, stack, pc->reg, true);
  auto frame_top = pc->reg;
  stack_save(state, stack, pc->reg, return_address(state, pc + 1));
  stack = adjust_stack_depth(state, stack, frame_top + 1);
  pc = set_new_pc(state, pc, stack, func);
  dispatch_next(pc, stack);
}
END OP_BEGIN(LCALLT) {
  argcnt = pc->data - 1;
  auto func = stack_load(state, stack, pc->reg, true);
  auto frame_top = pc->reg;
  stack_memmov(state, stack, frame_top + 1, argcnt);
  pc = set_new_pc(state, pc, stack, func);
  dispatch_next(pc, stack);
}
END OP_BEGIN(HALT) { return halt(state, stack); }
END
