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
#define VMGEN_TRACE_OP(pc, code, state, argcnt) ((void)0)
#endif

#ifndef OP_BEGIN
#define OP_BEGIN(code)                                                         \
  OP(code) {                                                                   \
    VMGEN_TRACE_OP(pc, code, state, argcnt);
#define END }
#endif

OP_BEGIN(ADD) {
  auto v1 = stack_load(state, stack, instr.v1, true);
  auto v2 = stack_load(state, stack, instr.v2, true);
  auto res = emit_ov_math_add(state, v1, v2);
  set_stack_top(state, instr.reg + 1);
  stack_save(state, stack, instr.reg, res);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(SUB) {
  auto v1 = stack_load(state, stack, instr.v1, true);
  auto v2 = stack_load(state, stack, instr.v2, true);
  auto res = emit_ov_math_sub(state, v1, v2);
  set_stack_top(state, instr.reg + 1);
  stack_save(state, stack, instr.reg, res);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(MOD) {
  auto v1 = stack_load(state, stack, instr.v1, true);
  auto v2 = stack_load(state, stack, instr.v2, true);
  auto res = emit_ov_math_mod(state, v1, v2);
  stack_save(state, stack, instr.reg, res);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(CONST) {
  auto c = const_load(state, pc, instr.data);
  stack_save(state, stack, instr.reg, c);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(KSHORT) {
  auto c = constify_data(state, instr.data);
  stack_save(state, stack, instr.reg, c);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(MOV) {
  auto c = stack_load(state, stack, instr.data, false);
  stack_save(state, stack, instr.reg, c);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(RET) {
  auto c = stack_load(state, stack, instr.reg, false);
  // TODO: re-enable.  This needs to be a MUCH lower priority, so we
  // don't record down-rec before up-rec.  Or alternatively, maybe
  // ONLY enable down-rec recording if the function has an up-rec trace already.

  auto res = check_record_start(pc, stack, state, op_table);
  if (res != op_table) {
    op_table = res;
    instr = *pc;
    dispatch_next(pc, stack);
  }
  auto old_op_table = op_table;
  auto frame = return_frame(state, instr, pc, stack, op_table);
  pc = frame.pc;
  stack = frame.stack;
  op_table = frame.ops;
  if (old_op_table != op_table) {
    instr = *pc;
  }
  dispatch_next(pc, stack);
}
END OP_BEGIN(LOOKUP) {
  auto c = const_load(state, pc, instr.data);
  // No need to check if c is a symbol, the compiler guarantees it
  auto v1 = sym_load(state, c);
  stack_save(state, stack, instr.reg, v1);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(DEFINE) {
  auto c = const_load(state, pc, instr.data);
  auto val = stack_load(state, stack, instr.reg, false);
  sym_store(state, c, val);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(WRITE) {
  auto val = stack_load(state, stack, instr.v1, false);
  obj_write(state, val, &op_table);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(FUNC) {
  // TODO argcnt check
  auto expect_argcnt = instr.reg;
  check_arity(expect_argcnt, argcnt);

  // TODO merge with arity check?
  check_expand_stack(state, &stack);
  auto old_ops = op_table;
  op_table = check_record_start(pc, stack, state, op_table);
  if (op_table != old_ops) {
    instr = *pc;
  }

  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(IFUNC) {
  auto expect_argcnt = instr.reg;
  check_arity(expect_argcnt, argcnt);
  check_expand_stack(state, &stack);

  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(JFUNC) {
  // TODO argcnt check - no, will be put in trace itself!
  auto f = instr.data;
  op_table = jit_func(&instr, &pc, &stack, state, op_table, &argcnt);

  /* if ((*pc).op != instr.op) { */
  /*   abort(); */
  /* } */
  op_func impl = ((op_func *)op_table)[instr.op];
  MUSTTAIL return impl(instr, pc, stack, state, op_table, argcnt);
}
#define CMP_BRANCH(OPNAME, EMIT_FN)                                            \
  END OP_BEGIN(OPNAME) {                                                       \
    auto v1 = stack_load(state, stack, instr.v1, true);                        \
    auto v2 = stack_load(state, stack, instr.v2, true);                        \
    auto res = EMIT_FN(state, pc, stack, v1, v2);                              \
    pc = branch_if_op(state, pc, stack, res);                                  \
    dispatch_next(pc, stack);                                                  \
  }

CMP_BRANCH(JLT, emit_math_cmp_lt)
CMP_BRANCH(JGT, emit_math_cmp_gt)
CMP_BRANCH(JLTE, emit_math_cmp_lte)
CMP_BRANCH(JGTE, emit_math_cmp_gte)
CMP_BRANCH(JEQV, emit_math_cmp_eq)
END OP_BEGIN(IF) {
  auto v = stack_load(state, stack, instr.data, false);
  auto res = emit_if_branch(state, pc, stack, v);
  pc = branch_if_op(state, pc, stack, res);
  dispatch_next(pc, stack);
}
END OP_BEGIN(JMP) {
  pc = vmgen_jmp_advance(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(CLOSURE_GET) {
  auto clo = stack_load(state, stack, instr.v1, false);
  fail_if_not_closure(clo);
  auto slot = instr.v2;
  auto res = closure_get(state, stack, clo, slot, instr.v1);
  stack_save(state, stack, instr.reg, res);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(CLOSURE_SET) {
  auto val = stack_load(state, stack, instr.reg, false);
  auto clo = stack_load(state, stack, instr.v1, false);
  auto slot = instr.v2;
  closure_set(state, clo, slot, val, &op_table);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(CLOSURE) {
  auto clo = closure_alloc(state, stack, pc);
  stack_save(state, stack, instr.reg, clo);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(LCALL) {
  argcnt = instr.data - 1;
  auto func = stack_load(state, stack, instr.reg, true);
  auto frame_top = instr.reg;
  stack_save(state, stack, instr.reg, return_address(state, pc + 1));
  stack = adjust_stack_depth(state, stack, frame_top + 1);
  pc = set_new_pc(state, pc, stack, func);
  dispatch_next(pc, stack);
}
END OP_BEGIN(LCALLT) {
  argcnt = instr.data - 1;
  auto func = stack_load(state, stack, instr.reg, true);
  auto frame_top = instr.reg;
  stack_memmov(state, stack, frame_top + 1, argcnt);
  pc = set_new_pc(state, pc, stack, func);
  dispatch_next(pc, stack);
}
END OP_BEGIN(ALLOC) {
  auto obj = alloc_obj(state, stack, pc);
  stack_save(state, stack, instr.reg, obj);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(STORE) {
  store_obj(state, stack, pc);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(GUARD) {
  auto res = guard_obj(state, stack, pc);
  stack_save(state, stack, instr.reg, res);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(LOAD) {
  auto res = load_obj(state, stack, pc);
  stack_save(state, stack, instr.reg, res);
  pc = next_op(pc);
  dispatch_next(pc, stack);
}
END OP_BEGIN(HALT) { return halt(state, stack); }
END
