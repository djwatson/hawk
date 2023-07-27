#include "asm_x64.h"
#include <assert.h>            // for assert
#include <capstone/capstone.h> // for cs_insn, cs_close, cs_disasm, cs_free
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>             // for printf, size_t
#include <stdlib.h>            // for exit
#include <valgrind/valgrind.h> // for VALGRIND_DISCARD_TRANSLATIONS
// TODO only for runtime symbol
#include "bytecode.h" // for INS_OP, INS_B
#include "emit_x64.h" // for emit_offset, emit_mov64, emit_mem_reg
#include "ir.h"       // for ir_ins, trace_s, ir_ins::(anonymous u...
#include "jitdump.h"  // for jit_dump, jit_reader_add, perf_map
#include "opcodes.h"  // for JLOOP, FUNC, LOOP
// only for tcache
#include "record.h" // for trace_cache_get, record_side
#include "types.h"  // for CONS_TAG, TAG_MASK, IMMEDIATE_MASK

#include "parallel_copy.h"
#include "third-party/stb_ds.h"

#define auto __auto_type
#define nullptr NULL

// TODO
long *expand_stack_slowpath(long *frame);
extern long *frame_top;
extern uint8_t *alloc_ptr;
extern uint8_t *alloc_end;

void disassemble(const uint8_t *code, int len) {
  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    return;
  }
  count = cs_disasm(handle, code, len, (uint64_t)code, 0, &insn);
  if (count > 0) {
    size_t j;
    for (j = 0; j < count; j++) {
      printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
             insn[j].op_str);
    }

    cs_free(insn, count);
  } else {
    printf("ERROR: Failed to disassemble given code!\n");
  }

  cs_close(&handle);
}

// clang-format off
const char *reg_names[] = {
  "rax",
  "rcx",
  "rdx",
  "rbx",
  "rsp",
  "rbp",
  "rsi",
  "rdi",
  "r8 ", 
  "r9 ", 
  "r10", 
  "r11", 
  "r12", 
  "r13", 
  "r14", 
  "r15",
  "   ",
};
// clang-format on

int get_free_reg(const int *slot) {
  for (int i = 0; i < regcnt; i++) {
    if (slot[i] == -1) {
      return i;
    }
  }
  printf("ERROR no free reg\n");
  exit(-1);
}

void maybe_assign_register(int v, trace_s *trace, int *slot) {
  if ((v & IR_CONST_BIAS) == 0) {
    auto op = &trace->ops[v];
    if (op->reg == REG_NONE) {
      op->reg = get_free_reg(slot);
      slot[op->reg] = v;
    }
  }
}

void assign_snap_registers(unsigned snap_num, int *slot, trace_s *trace) {
  auto snap = &trace->snaps[snap_num];
  for (uint64_t i = 0; i < arrlen(snap->slots); i++) {
    auto s = &snap->slots[i];
    if ((s->val & IR_CONST_BIAS) == 0) {
      maybe_assign_register(s->val, trace, slot);
    }
  }
}

typedef struct exit_state {
  long regs[regcnt];
  trace_s *trace;
  long snap;
} exit_state;

static void __attribute__((noinline)) __attribute__((naked))
jit_entry_stub(long *o_frame, Func fptr, exit_state *regs) {
  asm inline(".intel_syntax noprefix\n"
             //  Save callee-saved regs.
             "push rbx\n"
             "push rbp\n"
             "push r12\n"
             "push r13\n"
             "push r14\n"
             "push r15\n"

             // RDI: scheme frame ptr.
             "push rdx\n" // state regs
             "push rsi\n" // ptr to call.

             "mov r15, rdx\n" // state regs.

             // Put new reg state based on rcx param.
             "mov rax, [r15]\n"
             "mov rcx, [r15 + 8]\n"
             "mov rdx, [r15 + 16]\n"
             "mov rbx, [r15 + 24]\n"
             // RSP 32, c stack ptr.
             "mov rbp, [r15 + 40]\n"
             "mov rsi, [r15 + 48]\n"
             // RDI 56, scheme frame ptr.
             "mov r8, [r15 + 64]\n"
             "mov r9, [r15 + 72]\n"
             "mov r10, [r15 + 88]\n"
             "mov r11, [r15 + 96]\n"
             "mov r12, [r15 + 104]\n"
             "mov r13, [r15 + 112]\n"
             "mov r14, [r15 + 120]\n"
             "mov r15, [r15 + 128]\n"

             "pop r15\n"
             "jmp r15\n"
             :);
  // No need for clobbers, since hopefully the compiler will treat
  // jit_entry_stub as the normal sys-v calling convention.
}

static void __attribute__((noinline)) __attribute__((naked)) jit_exit_stub() {
  asm inline(".intel_syntax noprefix\n"
             //  Push reg state
             "mov r15, [rsp+16]\n"
             "mov [r15 + 116], r15\n"
             "mov [r15 + 112], r14\n"
             "mov [r15 + 104], r13\n"
             "mov [r15 + 96], r12\n"
             "mov [r15 + 88], r11\n"
             "mov [r15 + 80], r10\n"
             "mov [r15 + 72], r9\n"
             "mov [r15 + 64], r8\n"
             "mov [r15 + 56], rdi\n"
             "mov [r15 + 48], rsi\n"
             "mov [r15 + 40], rbp\n"
             "mov [r15 + 32], rsp\n"
             "mov [r15 + 24], rbx\n"
             "mov [r15 + 16], rdx\n"
             "mov [r15 + 8], rcx\n"
             "mov [r15], rax\n"
             "pop rax\n" // trace
             "mov [r15 + 128], rax\n"
             "pop rax\n" // exit num
             "mov [r15 + 136], rax\n"

             //  pop reg state
             "add rsp, 8\n"
             // pop callee-saved
             "pop r15\n"
             "pop r14\n"
             "pop r13\n"
             "pop r12\n"
             "pop rbp\n"
             "pop rbx\n"
             "ret\n"
             :);
}

void restore_snap(snap_s *snap, trace_s *trace, exit_state *state,
                  long **o_frame, unsigned int **o_pc) {
  (*o_frame) = (long *)state->regs[RDI];
  for (uint64_t i = 0; i < arrlen(snap->slots); i++) {
    auto slot = &snap->slots[i];
    if ((slot->val & IR_CONST_BIAS) != 0) {
      auto c = trace->consts[slot->val - IR_CONST_BIAS];
      (*o_frame)[slot->slot] = c & ~SNAP_FRAME;
    } else {
      (*o_frame)[slot->slot] = state->regs[trace->ops[slot->val].reg];
    }
  }

  (*o_pc) = snap->pc;
  (*o_frame) += snap->offset;
}

uint16_t find_reg_for_slot(int slot, snap_s *snap, trace_s *trace) {
  for (uint64_t i = 0; i < arrlen(snap->slots); i++) {
    auto s = &snap->slots[i];
    if (s->slot == slot) {
      if (s->val >= IR_CONST_BIAS) {
        return s->val;
      }
      return trace->ops[s->val].reg;
    }
  }
  assert(false);
  exit(-1);
}

void emit_snap(int snap, trace_s *trace, bool all) {
  printf("EMITSNAP: all %i\n", (int)all);
  auto sn = &trace->snaps[snap];
  int last_ret = -1;
  for (int i = (int)sn->ir - 1; i >= 0; i--) {
    if (trace->ops[i].op == IR_RET) {
      last_ret = i;
      break;
    }
  }
  // TODO frame size check
  for (uint64_t i = 0; i < arrlen(sn->slots); i++) {
    auto slot = &sn->slots[i];
    emit_check();
    // if (!all && (slot->slot >= sn->offset)) {
    //   break;
    // }
    if ((slot->val & IR_CONST_BIAS) != 0) {
      auto c = trace->consts[slot->val - IR_CONST_BIAS];
      // assert((c&SNAP_FRAME) < 32000);
      // printf("MOV %lx\n", c & ~SNAP_FRAME);
      emit_mem_reg(OP_MOV_RM, slot->slot * 8, RDI, R15);
      auto re = (reloc){emit_offset(), c, RELOC_ABS};
      arrput(trace->relocs, re);
      emit_mov64(R15, c & ~SNAP_FRAME);
    } else {
      auto op = &trace->ops[slot->val];
      // TODO RET check, can't emit past RETS
      if (slot->val > last_ret &&
          (op->op == IR_SLOAD && ((op->type & IR_INS_TYPE_GUARD) != 0)) &&
          op->op1 == slot->slot && slot->slot < sn->offset) {
        printf("DROPPING emit snap of slot %i\n", slot->slot);
        // nothing
      } else {
        emit_mem_reg(OP_MOV_RM, slot->slot * 8, RDI, op->reg);
      }
    }
  }
  // TODO check stack size
}

void emit_arith_op(enum ARITH_CODES arith_code, enum OPCODES op_code,
                   uint8_t reg, uint32_t op2, trace_s *trace, int32_t offset,
                   int *slot) {
  if ((op2 & IR_CONST_BIAS) != 0U) {
    long v = trace->consts[op2 - IR_CONST_BIAS];
    // TODO: check V is of correct type, but we typecheck return pointers also,
    // which can move.
    if ((long)((int32_t)v) == v) {
      emit_arith_imm(arith_code, reg, v);
    } else {
      emit_reg_reg(op_code, reg, R15);
      emit_mov64(R15, v);
    }
  } else {
    auto reg2 = trace->ops[op2].reg;
    emit_reg_reg(op_code, reg2, reg);
  }
}

void emit_arith(enum ARITH_CODES arith_code, enum OPCODES op_code, ir_ins *op,
                trace_s *trace, int32_t offset, int *slot) {
  maybe_assign_register(op->op1, trace, slot);
  maybe_assign_register(op->op2, trace, slot);

  emit_jcc32(JO, offset);

  auto reg2 = REG_NONE;
  if (!(op->op2 & IR_CONST_BIAS)) {
    reg2 = trace->ops[op->op2].reg;
  }

  auto reg1 = REG_NONE;
  if (!(op->op1 & IR_CONST_BIAS)) {
    reg1 = trace->ops[op->op1].reg;
  }
  auto reg = op->reg;
  if (reg != reg1 && reg2 == reg) {
    emit_reg_reg(op_code, R15, reg);
  } else {
    emit_arith_op(arith_code, op_code, reg, op->op2, trace, offset, slot);
  }
  if (op->op1 & IR_CONST_BIAS) {
    auto c = trace->consts[op->op1 - IR_CONST_BIAS];
    emit_mov64(reg, c);
  } else {
    reg1 = trace->ops[op->op1].reg;
    if (reg != reg1) {
      // TODO clownshow.  If we have a commutative OP (mul, add), we could just
      // run it backwards. ALternatively, ensure the reg allocator never does
      // this?
      if (reg2 == reg) {
        emit_reg_reg(OP_MOV, reg1, reg);
        emit_reg_reg(OP_MOV, reg2, R15);
      } else {
        emit_reg_reg(OP_MOV, reg1, reg);
      }
    }
  }
}

void emit_cmp(enum jcc_cond cmp, ir_ins *op, trace_s *trace, int32_t offset,
              int *slot) {
  maybe_assign_register(op->op1, trace, slot);
  maybe_assign_register(op->op2, trace, slot);

  emit_jcc32(cmp, offset);
  uint8_t reg = R15;
  if (!(op->op1 & IR_CONST_BIAS)) {
    reg = trace->ops[op->op1].reg;
  }
  emit_arith_op(OP_ARITH_CMP, OP_CMP, reg, op->op2, trace, offset, slot);
  if (op->op1 & IR_CONST_BIAS) {
    auto c = trace->consts[op->op1 - IR_CONST_BIAS];
    emit_mov64(R15, c);
  }
}

void emit_op_typecheck(uint8_t reg, uint8_t type, int32_t offset) {
  if ((type & IR_INS_TYPE_GUARD) != 0) {
    emit_jcc32(JNE, offset);
    if ((type & ~IR_INS_TYPE_GUARD) == 0) {
      emit_op_imm32(OP_TEST_IMM, 0, reg, 0x7);
    } else if ((type & TAG_MASK) == PTR_TAG) {
      // assert(false);
      printf("TODO typecheck ptr\n");
      emit_cmp_reg_imm32(R15, 1);
      emit_op_imm32(OP_AND_IMM, 4, R15, 0x7);
      emit_reg_reg(OP_MOV, reg, R15);
    } else if ((type & TAG_MASK) == LITERAL_TAG) {
      auto lit_bits = (type & IMMEDIATE_MASK) & ~IR_INS_TYPE_GUARD;
      emit_cmp_reg_imm32(R15, lit_bits);
      emit_op_imm32(OP_AND_IMM, 4, R15, 0xff);
      emit_reg_reg(OP_MOV, reg, R15);
    } else {
      emit_cmp_reg_imm32(R15, type & ~IR_INS_TYPE_GUARD);
      emit_op_imm32(OP_AND_IMM, 4, R15, 0x7);
      emit_reg_reg(OP_MOV, reg, R15);
    }
  }
}

void asm_jit(trace_s *trace, snap_s *side_exit, trace_s *parent) {
  emit_init();

  // Reg allocation
  int slot[regcnt];
  for (int i = 0; i < regcnt; i++) {
    slot[i] = -1;
  }
  // Unallocatable.
  slot[R15] = 0; // tmp.
  slot[RSP] = 0; // stack ptr.
  slot[RDI] = 0; // scheme frame ptr.

  uint64_t snap_labels[arrlen(trace->snaps)];

  auto end = emit_offset();

  emit_check();
  emit_jmp_abs(R15);
  emit_mov64(R15, (int64_t)jit_exit_stub);
  emit_check();
  emit_push(R15);
  emit_mov64(R15, (int64_t)trace);
  emit_push(R15);

  auto exit_label = emit_offset();

  for (long i = arrlen(trace->snaps) - 1; i >= 0; i--) {
    emit_check();
    // Funny embed here, so we can patch later.
    // emit_jmp_rel(exit_label - emit_offset());
    trace->snaps[i].patchpoint = emit_offset();
    emit_jmp32(exit_label - emit_offset());
    emit_mov64(R15, i);
    snap_labels[i] = emit_offset();
  }

  uint64_t loop_offset_label = 0;

  if (trace->link != -1) {
    auto *otrace = trace_cache_get(trace->link);
    emit_check();

    if (otrace != trace) {
      emit_jmp_abs(R15);
      emit_mov64(R15, (uint64_t)otrace->fn);
    } else {
      // Patched at top.
      loop_offset_label = emit_offset();
      emit_jmp32(0);
    }

    emit_check();
    auto last_snap = &trace->snaps[arrlen(trace->snaps) - 1];
    if (last_snap->offset != 0U) {
      emit_arith_imm(OP_ARITH_ADD, RDI, last_snap->offset * 8);
      auto ok = emit_offset();
      // Emit a stack overflow check
      if (last_snap->offset > 0) {
        emit_reg_reg(OP_MOV, RAX, RDI);
        emit_call_indirect(R15);
        emit_mov64(R15, (int64_t)&expand_stack_slowpath);
        emit_jcc32(JBE, ok - emit_offset());
        emit_reg_reg(OP_CMP, R15, RDI);
        // TODO merge if in top?
        emit_mem_reg(OP_MOV_MR, 0, R15, R15);
        emit_mov64(R15, (uint64_t)&frame_top);
      }
    }

    //     // Parallel move if there are args
    //     {
    //       std::multimap<uint64_t, uint64_t> moves;
    //       std::vector<std::pair<int, uint16_t>> consts;
    //       for (size_t op_cnt2 = 0; op_cnt2 < arrlen(otrace->ops); op_cnt2++)
    //       {
    // 	auto&op = otrace->ops[op_cnt2];
    // 	// TODO parent type
    // 	if (op.op != IR_ARG) {
    // 	  break;
    // 	}
    // 	auto oldreg = find_reg_for_slot(op.op1 + last_snap->offset, &last_snap,
    // trace); 	if (oldreg >= IR_CONST_BIAS) {
    // 	  consts.push_back(std::make_pair(op.reg, oldreg));
    // 	} else {
    // 	  moves.insert(std::make_pair(oldreg, op.reg));
    // 	}
    //       }
    //       auto res = serialize_parallel_copy(moves, 12 /* r15 */);
    //       printf("Parellel copy:\n");
    //       for(auto&mov: moves) {
    // 	printf(" %li to %li\n", mov.first, mov.second);
    //       }
    //       printf("----------------\n");
    //       for(auto&mov : res) {
    // 	a.mov(ir_to_asmjit[mov.second], ir_to_asmjit[mov.first]);
    //       }
    //       for(auto&c : consts) {
    // 	auto con = trace->consts[c.second - IR_CONST_BIAS];
    // 	a.mov(ir_to_asmjit[c.first], con & ~SNAP_FRAME);
    //       }
    //     }
    assign_snap_registers(arrlen(trace->snaps) - 1, slot, trace);
    emit_snap(arrlen(trace->snaps) - 1, trace,
              (INS_OP(otrace->startpc) != FUNC));
  } else {
    // No link, jump back to interpreter loop.
    emit_check();
    emit_jmp32(exit_label - emit_offset());
    emit_mov64(R15, arrlen(trace->snaps) - 1);
  }

  // Main generation loop
  long cur_snap = arrlen(trace->snaps) - 1;
  long op_cnt = arrlen(trace->ops) - 1;
  assign_snap_registers(cur_snap, slot, trace);
  for (; op_cnt >= 0; op_cnt--) {
    while (cur_snap >= 0 && trace->snaps[cur_snap].ir > op_cnt) {
      if (cur_snap > 0) {
        assign_snap_registers(cur_snap - 1, slot, trace);
      }
      cur_snap--;
    }
    auto op = &trace->ops[op_cnt];

    // free current register.
    if (op->reg != REG_NONE) {
      assert(slot[op->reg] == op_cnt);
      slot[op->reg] = -1;
    }

    emit_check();
    switch (op->op) {
    case IR_SLOAD: {
      // frame pointer in RDI
      auto reg = op->reg;
      if ((op->type & IR_INS_TYPE_GUARD) == 0) {
        goto done;
      }
      emit_op_typecheck(reg, op->type, snap_labels[cur_snap] - emit_offset());
      emit_mem_reg(OP_MOV_MR, op->op1 * 8, RDI, reg);
      break;
    }
    case IR_CAR: {
      maybe_assign_register(op->op1, trace, slot);
      auto reg = op->reg;
      if (reg == REG_NONE) {
        reg = R15; // Unused, but potentially used by JGUARD.
      }
      emit_op_typecheck(reg, op->type, snap_labels[cur_snap] - emit_offset());
      if (ir_is_const(op->op1)) {
        emit_mem_reg(OP_MOV_MR, 8 - CONS_TAG, reg, reg);
        emit_mov64(reg, trace->consts[op->op1 - IR_CONST_BIAS]);
      } else {
        auto reg1 = trace->ops[op->op1].reg;
        emit_mem_reg(OP_MOV_MR, 8 - CONS_TAG, reg1, reg);
      }
      break;
    }
    case IR_CDR: {
      maybe_assign_register(op->op1, trace, slot);
      auto reg = op->reg;
      if (reg == REG_NONE) {
        reg = R15; // Unused, but potentially used by JGUARD.
      }
      emit_op_typecheck(reg, op->type, snap_labels[cur_snap] - emit_offset());
      if (ir_is_const(op->op1)) {
        emit_mem_reg(OP_MOV_MR, 16 - CONS_TAG, reg, reg);
        emit_mov64(reg, trace->consts[op->op1 - IR_CONST_BIAS]);
      } else {
        auto reg1 = trace->ops[op->op1].reg;
        emit_mem_reg(OP_MOV_MR, 16 - CONS_TAG, reg1, reg);
      }
      break;
    }
    case IR_GGET: {
      auto *sym =
          (symbol *)(trace->consts[op->op1 - IR_CONST_BIAS] - SYMBOL_TAG);
      auto reg = op->reg;
      emit_op_typecheck(reg, op->type, snap_labels[cur_snap] - emit_offset());
      emit_mem_reg(OP_MOV_MR, 0, reg, reg);
      auto re = (reloc){emit_offset(), trace->consts[op->op1 - IR_CONST_BIAS],
                        RELOC_SYM_ABS};
      arrput(trace->relocs, re);
      emit_mov64(reg, (int64_t)&sym->val);
      break;
    }
    case IR_STORE: {
      maybe_assign_register(op->op1, trace, slot);
      maybe_assign_register(op->op2, trace, slot);
      assert(!(op->op1 & IR_CONST_BIAS));
      assert(trace->ops[op->op1].op == IR_REF ||
             trace->ops[op->op1].op == IR_VREF);
      if (op->op2 & IR_CONST_BIAS) {
        emit_mem_reg(OP_MOV_RM, 0, trace->ops[op->op1].reg, R15);
        auto c = trace->consts[op->op2 - IR_CONST_BIAS];
        emit_mov64(R15, c);
      } else {
        emit_mem_reg(OP_MOV_RM, 0, trace->ops[op->op1].reg,
                     trace->ops[op->op2].reg);
      }
      break;
    }
    case IR_LOAD: {
      maybe_assign_register(op->op1, trace, slot);
      maybe_assign_register(op->op2, trace, slot);
      assert(op->reg != REG_NONE);
      assert(!ir_is_const(op->op1));
      assert(!ir_is_const(op->op2));
      assert(trace->ops[op->op1].op == IR_REF ||
             trace->ops[op->op1].op == IR_VREF);
      if (op->op2 & IR_CONST_BIAS) {
        emit_mem_reg(OP_MOV_RM, 0, trace->ops[op->op1].reg, R15);
        auto c = trace->consts[op->op2 - IR_CONST_BIAS];
        emit_mov64(R15, c);
      } else {
        emit_mem_reg(OP_MOV_MR, 0, trace->ops[op->op1].reg, op->reg);
      }
      break;
    }
    case IR_ABC: {
      printf("TODO: ABC emit\n");
      break;
    }
    case IR_VREF: {
      // TODO: fuse.
      maybe_assign_register(op->op1, trace, slot);
      maybe_assign_register(op->op2, trace, slot);
      emit_mem_reg_sib(OP_LEA, 8 - PTR_TAG, 0, trace->ops[op->op2].reg,
                       trace->ops[op->op1].reg, op->reg);
      break;
    }
    case IR_REF: {
      // TODO: fuse.
      maybe_assign_register(op->op1, trace, slot);
      emit_mem_reg(OP_LEA, op->op2, trace->ops[op->op1].reg, op->reg);
      break;
    }
    case IR_ALLOC: {
      emit_arith_imm(OP_ARITH_ADD, op->reg, CONS_TAG);
      emit_mem_reg(OP_MOV_RM, 0, op->reg, R15);
      emit_mov64(R15, CONS_TAG);
      emit_arith_imm(OP_ARITH_SUB, op->reg, op->op1);
      emit_mem_reg(OP_MOV_RM, 0, R15, op->reg);
      emit_mov64(R15, (uint64_t)&alloc_ptr);
      // TODO call GC directly?
      emit_jcc32(JGE, snap_labels[cur_snap] - emit_offset());
      emit_reg_reg(OP_CMP, R15, op->reg);
      emit_arith_imm(OP_ARITH_ADD, op->reg, op->op1);
      emit_mem_reg(OP_MOV_MR, 0, op->reg, op->reg);
      emit_mem_reg(OP_MOV_MR, 0, R15, R15);
      emit_mov64(op->reg, (uint64_t)&alloc_ptr);
      emit_mov64(R15, (uint64_t)&alloc_end);

      break;
    }
      //     case IR_CLT: {
      //       assert(!(op->op1 & IR_CONST_BIAS));
      //       auto reg = ir_to_asmjit[op->reg];
      //       // beware of colision with one of the other regs
      //       auto reg1 = ir_to_asmjit[trace->ops[op->op1].reg];
      //       if (op->op2 & IR_CONST_BIAS) {
      //         long v = trace->consts[op->op2 - IR_CONST_BIAS];
      //         assert(v < 32000);
      //         a.cmp(reg1, v);
      //       } else {
      //         auto reg2 = ir_to_asmjit[trace->ops[op->op2].reg];
      //         a.cmp(reg1, reg2);
      //       }
      //       // Zero the reg without touching flags.
      //       // Note reg may be the same as reg1 or reg2,
      //       // so we can't xor first.
      //       //a.lea(reg, x86::ptr_abs(0));
      //       //a.setl(reg.r8Lo());

      //       a.mov(reg, FALSE_REP);
      //       a.mov(x86::r15, TRUE_REP);
      //       a.cmovl(reg, x86::r15);
      //       //      a.shl(reg, 3); // TODO
      //       break;
      //     }
    case IR_EQ: {
      emit_cmp(JNE, op, trace, snap_labels[cur_snap] - emit_offset(), slot);
      break;
    }
    case IR_NE: {
      emit_cmp(JE, op, trace, snap_labels[cur_snap] - emit_offset(), slot);
      break;
    }
    case IR_GE: {
      emit_cmp(JL, op, trace, snap_labels[cur_snap] - emit_offset(), slot);
      break;
    }
    case IR_LT: {
      emit_cmp(JGE, op, trace, snap_labels[cur_snap] - emit_offset(), slot);
      break;
    }
    case IR_ADD: {
      emit_arith(OP_ARITH_ADD, OP_ADD, op, trace,
                 snap_labels[cur_snap] - emit_offset(), slot);
      break;
    }
    case IR_SUB: {
      emit_arith(OP_ARITH_SUB, OP_SUB, op, trace,
                 snap_labels[cur_snap] - emit_offset(), slot);
      break;
    }
      //     case IR_LOOP: {
      //       printf("------------LOOP-------------\n");
      //       a.bind(loop_label);
      //       use_loop = true;
      //       break;
      //     }
      //     case IR_PHI: {
      //       auto reg1 = ir_to_asmjit[trace->ops[op->op1].reg];
      //       auto reg2 = ir_to_asmjit[trace->ops[op->op2].reg];
      //       if(reg1 != reg2) {
      // 	a.mov(reg1, reg2);
      //       }
      //       break;
      //     }
    case IR_RET: {
      // TODO reloc if functions can move.
      auto retadd = trace->consts[op->op1 - IR_CONST_BIAS] - SNAP_FRAME;
      auto b = trace->consts[op->op2 - IR_CONST_BIAS];

      emit_arith_imm(OP_ARITH_SUB, RDI, b);
      emit_jcc32(JNE, snap_labels[cur_snap] - emit_offset());

      emit_mem_reg(OP_CMP, -8, RDI, R15);

      emit_mov64(R15, retadd);

      break;
    }
    default: {
      printf("Can't jit op: %s\n", ir_names[(int)op->op]);
      exit(-1);
    }
    }
  }

done:
  // TODO parent loads should have separate TAG
  {
    map moves;
    map res;
    moves.mp_sz = 0;
    for (; op_cnt >= 0; op_cnt--) {
      auto op = &trace->ops[op_cnt];
      map_insert(&moves, find_reg_for_slot(op->op1, side_exit, parent),
                 op->reg);
    }
    serialize_parallel_copy(&moves, &res, R15);
    for (int64_t i = res.mp_sz - 1; i >= 0; i--) {
      emit_reg_reg(OP_MOV, res.mp[i].from, res.mp[i].to);
    }
  }

  auto start = emit_offset();
  if (loop_offset_label != 0U) {
    emit_bind(start, loop_offset_label);
  }
  Func fn = (Func)start;

  trace->fn = fn;
  auto len = end - start;
  disassemble((const uint8_t *)fn, len);

  if (side_exit != nullptr) {
    emit_bind(start, side_exit->patchpoint);
  }

  perf_map((uint64_t)fn, len, "Trace");
  jit_dump(len, (uint64_t)fn, "Trace");
  jit_reader_add(len, (uint64_t)fn, 0, 0, "Trace");
  VALGRIND_DISCARD_TRANSLATIONS(fn, len);
}

extern unsigned int *patchpc;
extern unsigned int patchold;
int jit_run(unsigned int tnum, unsigned int **o_pc, long **o_frame) {
  exit_state state;
  auto *trace = trace_cache_get(tnum);

  for (uint64_t i = 0; i < arrlen(trace->ops); i++) {
    auto op = &trace->ops[i];
    if (op->op != IR_ARG) {
      break;
    }
    state.regs[op->reg] = (*o_frame)[op->op1];
  }

  // printf("FN start %i\n", tnum);
  jit_entry_stub(*o_frame, trace->fn, &state);
  trace = state.trace;
  long unsigned exit = state.snap;
  auto *snap = &trace->snaps[exit];

  restore_snap(snap, trace, &state, o_frame, o_pc);
  // auto func = find_func_for_frame(snap->pc);
  // assert(func);
  //  printf("exit %li from trace %i new pc %li func %s\n", exit, trace->num,
  //  snap->pc - &func->code[0], func->name.c_str());

  if (exit != arrlen(trace->snaps) - 1) {
    if (snap->exits < 10) {
      snap->exits++;
    } else {
      if (snap->exits < 14) {
        snap->exits++;
        printf("Hot snap %li\n", exit);
        if (INS_OP(**o_pc) == JLOOP) {
          printf("HOT SNAP to JLOOP\n");
          patchpc = *o_pc;
          patchold = **o_pc;
          auto *otrace = trace_cache_get(INS_B(**o_pc));
          **o_pc = otrace->startpc;
        }
        record_side(trace, snap);
        return 1;
      }
      if (snap->exits == 14) {
        printf("Side max\n");
        snap->exits++;
      }
    }
    // TODO this may or may not be working as intended:
    // Should only replace if *this trace*'s start PC is o_pc,
    // and it's originaly a RET, i.e. we predicted the RET wrong.
    if (INS_OP(**o_pc) == JLOOP) {
      // TODO make work for both RET1 and JLOOP
      auto *otrace = trace_cache_get(INS_B(**o_pc));
      if (INS_OP(otrace->startpc) == LOOP) {
        (*o_pc)++;
      } else {
        *o_pc = &otrace->startpc;
      }
      // printf("Exit to loop\n");
      return 0;
    }
  }

  // printf("FN return\n");
  return 0;
}
