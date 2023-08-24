#include "asm_x64.h"
#include <assert.h>            // for assert
#ifdef CAPSTONE
#include <capstone/capstone.h> // for cs_insn, cs_close, cs_disasm, cs_free
#endif
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>             // for printf, size_t
#include <stdlib.h>            // for exit
#ifdef VALGRIND
#include <valgrind/valgrind.h> // for VALGRIND_DISCARD_TRANSLATIONS
#endif
// TODO only for runtime symbol
#include "bytecode.h" // for INS_OP, INS_B
#include "emit_x64.h" // for emit_offset, emit_mov64, emit_mem_reg
#include "ir.h"       // for ir_ins, trace_s, ir_ins::(anonymous u...
#ifdef JITDUMP
#include "jitdump.h"  // for jit_dump, jit_reader_add, perf_map
#endif
#include "opcodes.h"  // for JLOOP, FUNC, LOOP
// only for tcache
#include "record.h" // for trace_cache_get, record_side
#include "types.h"  // for CONS_TAG, TAG_MASK, IMMEDIATE_MASK

#include "vm.h"

#include "parallel_copy.h"
#include "third-party/stb_ds.h"

#define auto __auto_type
#define nullptr NULL

#include "lru.c"

// TODO
long *expand_stack_slowpath(long *frame);
extern long *frame_top;
extern uint8_t *alloc_ptr;
extern uint8_t *alloc_end;

bool jit_dump_flag = false;

int64_t spill_slot[256];
lru reg_lru;

void disassemble(const uint8_t *code, int len) {
#ifdef CAPSTONE
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
#endif
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
bool reg_callee[] = {
  false, // rax
  false,  // rcx
  false, // rdx
  true, // rbx
  true,  // rsp
  true,  // rbp
  false, // rsi
  false, // rdi
  false, // r8
  false, // r9
  false, // r10
  false, // r11
  true,  // r12
  true,  // r13
  true,  // r14
  true,  // r15
};
// clang-format on

int get_free_reg(trace_s* trace, uint32_t* next_spill, int *slot, bool callee) {
  for (int i = 0; i < regcnt; i++) {
    if (slot[i] == -1) {
      if (!callee || reg_callee[i]) {
	return i;
      }
    }
  }

  // Poke the unusable slots.
  lru_poke(&reg_lru, R15);
  lru_poke(&reg_lru, RSP);
  lru_poke(&reg_lru, RDI);
  
  // Spill.
  auto oldest = lru_oldest(&reg_lru);
  assert(oldest < REG_NONE);
  printf("Spilling reg %s\n", reg_names[oldest]);
  auto op = slot[oldest];
  assert(trace->ops[op].reg != REG_NONE);

  auto spill = trace->ops[op].slot;
  if (trace->ops[op].slot == SLOT_NONE) {
    spill = (*next_spill)++;
    assert(spill <= 255);
  }

  trace->ops[op].slot = spill;
  emit_mem_reg(OP_MOV_MR, 0, R15, trace->ops[op].reg);
  emit_mov64(R15, (int64_t)&spill_slot[trace->ops[op].slot]);
  trace->ops[op].reg = REG_NONE;
  slot[oldest] = -1;

  
  return oldest;
}

// Re-assign non-callee saved regs to callee saved.
void preserve_for_call(trace_s* trace, int *slot, uint32_t* next_spill) {
  for (int i = 0; i < regcnt; i++) {
    if (i != RDI && slot[i] != -1 && !reg_callee[i]) {
      auto op = slot[i];
      auto spill = trace->ops[op].slot;
      if (trace->ops[op].slot == SLOT_NONE) {
	// Reload from new spill slot
	// We don't need to store here, original instruction will store.
	spill = (*next_spill)++;
	assert(spill <= 255);
      }
      trace->ops[op].slot = spill;
      printf("Assigning spill slot %i to op %i, mov to reg %s\n", spill, op, reg_names[trace->ops[op].reg]);
      
      emit_mem_reg(OP_MOV_MR, 0, R15, trace->ops[op].reg);
      emit_mov64(R15, (int64_t)&spill_slot[trace->ops[op].slot]);
      trace->ops[op].reg = REG_NONE;
      slot[i] = -1;
    }
  }
}

void maybe_assign_register(int v, trace_s *trace, int *slot, uint32_t*next_spill) {
  if ((v & IR_CONST_BIAS) == 0) {
    auto op = &trace->ops[v];
    if (op->reg == REG_NONE) {
      op->reg = get_free_reg(trace, next_spill, slot, false);
      slot[op->reg] = v;

      // Reload from spill slot.
      if (op->slot != SLOT_NONE) {
	printf("Assigning register %s to op %i spilled slot %i\n", reg_names[op->reg], v, op->slot);
      }
	printf("Assigning register %s to op %i\n", reg_names[op->reg], v);
    } 
    lru_poke(&reg_lru, op->reg);
  }
}

void assign_snap_registers(unsigned snap_num, int *slot, trace_s *trace, uint32_t* next_spill) {
  auto snap = &trace->snaps[snap_num];
  for (uint64_t i = 0; i < arrlen(snap->slots); i++) {
    auto s = &snap->slots[i];
    if ((s->val & IR_CONST_BIAS) == 0) {
      maybe_assign_register(s->val, trace, slot, next_spill);
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
      (*o_frame)[slot->slot] = (long)(c);
    } else {
      if (trace->ops[slot->val].slot != SLOT_NONE) {
	// Was spilled, restore from spill slot.
	(*o_frame)[slot->slot] = spill_slot[trace->ops[slot->val].slot];	
      } else {
	// Restore from register.
	(*o_frame)[slot->slot] = state->regs[trace->ops[slot->val].reg];
      }
    }
  }

  (*o_pc) = snap->pc;
  (*o_frame) += snap->offset;
}

uint16_t find_val_for_slot(int slot, snap_s *snap, trace_s *trace) {
  for (uint64_t i = 0; i < arrlen(snap->slots); i++) {
    auto s = &snap->slots[i];
    if (s->slot == slot) {
      return s->val;
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
  for (uint64_t i = 0; i < arrlen(sn->slots); i++) {
    auto slot = &sn->slots[i];
    emit_check();
    // if (!all && (slot->slot >= sn->offset)) {
    //   break;
    // }
    if ((slot->val & IR_CONST_BIAS) != 0) {
      auto c = trace->consts[slot->val - IR_CONST_BIAS];
      emit_mem_reg(OP_MOV_RM, slot->slot * 8, RDI, R15);
      auto re = (reloc){emit_offset(), c, RELOC_ABS};
      arrput(trace->relocs, re);
      emit_mov64(R15, (int64_t)(c));
    } else {
      auto op = &trace->ops[slot->val];
      // TODO RET check, can't emit past RETS
      if (slot->val > last_ret &&
          (op->op == IR_SLOAD && ((op->type & IR_INS_TYPE_GUARD) != 0)) &&
          op->op1 == slot->slot && slot->slot < sn->offset) {
        printf("DROPPING emit snap of slot %i\n", slot->slot);
        // nothing
      } else if (op->slot != SLOT_NONE) {
	// Reload from spill.
	// TODO could use the real reg, if we did this in the same order as allocation
	// (i.e. reverse order??).
	emit_mem_reg(OP_MOV_RM, slot->slot * 8, RDI, R15);
	emit_mem_reg(OP_MOV_MR, 0, R15, R15);
	emit_mov64(R15, (int64_t)&spill_slot[op->slot]);
      } else {
	emit_mem_reg(OP_MOV_RM, slot->slot * 8, RDI, op->reg);
      }
    }
  }
}

void emit_arith_op(enum ARITH_CODES arith_code, enum OPCODES op_code,
                   uint8_t reg, uint32_t op2, trace_s *trace, int *slot) {
  if ((op2 & IR_CONST_BIAS) != 0U) {
    long v = trace->consts[op2 - IR_CONST_BIAS];
    // TODO: check V is of correct type, but we typecheck return pointers also,
    // which can move.
    if ((long)((int32_t)v) == v) {
      emit_arith_imm(arith_code, reg, (int32_t)v);
    } else {
      emit_reg_reg(op_code, reg, R15);
      // This is only necessary for cmp of a closure for call/callt
      auto re = (reloc){emit_offset(), v, RELOC_ABS};
      arrput(trace->relocs, re);
      emit_mov64(R15, v);
    }
  } else {
    auto reg2 = trace->ops[op2].reg;
    emit_reg_reg(op_code, reg2, reg);
  }
}

void emit_arith(enum ARITH_CODES arith_code, enum OPCODES op_code, ir_ins *op,
                trace_s *trace, uint64_t offset, int *slot, uint32_t* next_spill) {
  maybe_assign_register(op->op1, trace, slot, next_spill);
  maybe_assign_register(op->op2, trace, slot, next_spill);

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
    emit_arith_op(arith_code, op_code, reg, op->op2, trace, slot);
  }
  if (op->op1 & IR_CONST_BIAS) {
    auto c = trace->consts[op->op1 - IR_CONST_BIAS];
    auto re = (reloc){emit_offset(), c, RELOC_ABS};
    arrput(trace->relocs, re);
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

void emit_cmp(enum jcc_cond cmp, ir_ins *op, trace_s *trace, uint64_t offset,
              int *slot, uint32_t*next_spill) {
  maybe_assign_register(op->op1, trace, slot, next_spill);
  maybe_assign_register(op->op2, trace, slot, next_spill);

  // TODO pass snap label instead, calculate offset
  emit_jcc32(cmp, offset);
  uint8_t reg;
  if (!ir_is_const(op->op1)) {
    reg = trace->ops[op->op1].reg;
  } else {
    // Find a tmp reg.
    if (ir_is_const(op->op2)) {
      reg = get_free_reg(trace, next_spill, slot, false);
    } else {
      reg = R15;
    }
  }
  emit_arith_op(OP_ARITH_CMP, OP_CMP, reg, op->op2, trace, slot);
  if (ir_is_const(op->op1)) {
    auto c = trace->consts[op->op1 - IR_CONST_BIAS];
    auto re = (reloc){emit_offset(), c, RELOC_ABS};
    arrput(trace->relocs, re);
    emit_mov64(reg, c);
  }
}

void emit_op_typecheck(uint8_t reg, uint8_t type, uint64_t offset) {
  if ((type & IR_INS_TYPE_GUARD) != 0) {
    emit_jcc32(JNE, offset);
    if ((type & ~IR_INS_TYPE_GUARD) == 0) {
      emit_op_imm32(OP_TEST_IMM, 0, reg, 0x7);
    } else if ((type & TAG_MASK) == PTR_TAG) {
      emit_cmp_reg_imm32(R15, type & ~IR_INS_TYPE_GUARD);
      emit_mem_reg(OP_MOV_MR, -PTR_TAG, R15, R15);
      emit_reg_reg(OP_MOV, reg, R15);
      // TODO clean offsets up a bit.
      emit_jcc32(JNE, offset);
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
  lru_init(&reg_lru);

  uint32_t next_spill = 1;

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
    // TODO check int32_t
    emit_jmp32((int32_t)(exit_label - emit_offset()));
    emit_mov64(R15, i);
    snap_labels[i] = emit_offset();
  }

  uint64_t loop_offset_label = 0;

  if (trace->link != -1) {
    auto *otrace = trace_cache_get(trace->link);
    emit_check();

    if (otrace != trace) {
      emit_jmp_abs(R15);
      emit_mov64(R15, (int64_t)otrace->fn);
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
	// TODO check offset
        emit_jcc32(JBE, ok);
        emit_reg_reg(OP_CMP, R15, RDI);
        // TODO merge if in top?
        emit_mem_reg(OP_MOV_MR, 0L, R15, R15);
        emit_mov64(R15, (int64_t)&frame_top);
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
    assign_snap_registers(arrlen(trace->snaps) - 1, slot, trace, &next_spill);
    emit_snap(arrlen(trace->snaps) - 1, trace,
              (INS_OP(otrace->startpc) != FUNC));
  } else {
    // No link, jump back to interpreter loop.
    emit_check();
    // TODO check offset
    emit_jmp32((int32_t)(exit_label - emit_offset()));
    emit_mov64(R15, arrlen(trace->snaps) - 1);
  }

  // Main generation loop
  long cur_snap = arrlen(trace->snaps) - 1;
  long op_cnt = arrlen(trace->ops) - 1;
  assign_snap_registers(cur_snap, slot, trace, &next_spill);
  for (; op_cnt >= 0; op_cnt--) {
    while (cur_snap >= 0 && trace->snaps[cur_snap].ir > op_cnt) {
      if (cur_snap > 0) {
        assign_snap_registers(cur_snap - 1, slot, trace, &next_spill);
      }
      cur_snap--;
    }
    auto op = &trace->ops[op_cnt];

    // Check for spill
    if (op->slot != SLOT_NONE) {
      if (op->reg == REG_NONE) {
	maybe_assign_register(op_cnt, trace, slot, &next_spill);
      }
      printf("Spilling op %li to slot %i from reg %s\n", op_cnt, op->slot, reg_names[op->reg]);
      emit_mem_reg(OP_MOV_RM, 0, R15, op->reg);
      emit_mov64(R15, (int64_t)&spill_slot[op->slot]);
    }
    /* if (op->reg == REG_NONE) { */
    /*   printf("WARNING: emitting op with no reg: %i\n", op_cnt); */
    /* } */
    
    // free current register.
    if (op->reg != REG_NONE) {
      assert(slot[op->reg] == op_cnt);
      slot[op->reg] = -1;
    }

    emit_check();
    switch (op->op) {
    case IR_SLOAD: {
      // Used for typecheck only
      if (op->reg == REG_NONE) {
	op->reg = get_free_reg(trace, &next_spill, slot, false);
	printf("EMIT LOAD ONLY\n");
      }
      // frame pointer in RDI
      auto reg = op->reg;
      if ((op->type & IR_INS_TYPE_GUARD) == 0) {
        goto done;
      }
      emit_op_typecheck(reg, op->type, snap_labels[cur_snap]);
      emit_mem_reg(OP_MOV_MR, op->op1 * 8, RDI, reg);
      break;
    }
    case IR_GGET: {
      // Used for typecheck only
      if (op->reg == REG_NONE) {
	op->reg = get_free_reg(trace, &next_spill, slot, false);
      }
      auto *sym =
          (symbol *)(trace->consts[op->op1 - IR_CONST_BIAS] - SYMBOL_TAG);
      auto reg = op->reg;
      emit_op_typecheck(reg, op->type, snap_labels[cur_snap]);
      emit_mem_reg(OP_MOV_MR, 0, reg, reg);
      auto re = (reloc){emit_offset(), trace->consts[op->op1 - IR_CONST_BIAS],
                        RELOC_SYM_ABS};
      arrput(trace->relocs, re);
      emit_mov64(reg, (int64_t)&sym->val);
      break;
    }
    case IR_GSET: {
      maybe_assign_register(op->op2, trace, slot, &next_spill);
      auto *sym =
          (symbol *)(trace->consts[op->op1 - IR_CONST_BIAS] - SYMBOL_TAG);
      if (ir_is_const(op->op2)) {
        auto c = trace->consts[op->op2 - IR_CONST_BIAS];
	auto r = get_free_reg(trace, &next_spill, slot, false);
	emit_mem_reg(OP_MOV_RM, 0, R15, r);
	auto re = (reloc){emit_offset(), c, RELOC_ABS};
	arrput(trace->relocs, re);
	emit_mov64(r, c);
      } else {
	emit_mem_reg(OP_MOV_RM, 0, R15, trace->ops[op->op2].reg);
      }
      auto re = (reloc){emit_offset(), trace->consts[op->op1 - IR_CONST_BIAS],
	RELOC_SYM_ABS};
      arrput(trace->relocs, re);
      emit_mov64(R15, (int64_t)&sym->val);
      break;
    }
    case IR_STRST: {
      maybe_assign_register(op->op1, trace, slot, &next_spill);
      maybe_assign_register(op->op2, trace, slot, &next_spill);
      assert(!(op->op1 & IR_CONST_BIAS));
      assert(trace->ops[op->op1].op == IR_STRREF);
      if (op->op2 & IR_CONST_BIAS) {
        emit_mem_reg(OP_MOV8, 0, trace->ops[op->op1].reg, R15);
	// must be fixnum
        uint8_t c = trace->consts[op->op2 - IR_CONST_BIAS] >> 8;
        emit_mov64(R15, c);
      } else {
        emit_mem_reg(OP_MOV8, 0, trace->ops[op->op1].reg, R15);
	emit_imm8(8); // untag
	emit_reg_reg(OP_SAR_CONST, 7, R15);
	emit_reg_reg(OP_MOV_MR, R15, trace->ops[op->op2].reg);
      }
      break;
    }
    case IR_STORE: {
      maybe_assign_register(op->op1, trace, slot, &next_spill);
      maybe_assign_register(op->op2, trace, slot, &next_spill);
      assert(!(op->op1 & IR_CONST_BIAS));
      assert(trace->ops[op->op1].op == IR_REF ||
             trace->ops[op->op1].op == IR_VREF);
      if (op->op2 & IR_CONST_BIAS) {
        emit_mem_reg(OP_MOV_RM, 0, trace->ops[op->op1].reg, R15);
        auto c = trace->consts[op->op2 - IR_CONST_BIAS];
	auto re = (reloc){emit_offset(), c, RELOC_ABS};
	arrput(trace->relocs, re);
        emit_mov64(R15, c);
      } else {
        emit_mem_reg(OP_MOV_RM, 0, trace->ops[op->op1].reg,
                     trace->ops[op->op2].reg);
      }
      break;
    }
    case IR_STRLD: {
      maybe_assign_register(op->op1, trace, slot, &next_spill);
      maybe_assign_register(op->op2, trace, slot, &next_spill);
      assert(!ir_is_const(op->op1)); // str

      emit_arith_imm(OP_ARITH_ADD, op->reg, CHAR_TAG);
      emit_imm8(8);
      emit_reg_reg(OP_SAR_CONST, 4, op->reg);
      emit_mem_reg2(OP_MOVZX8, 0, op->reg, op->reg);
      if(!ir_is_const(op->op2)) {
	emit_mem_reg_sib(OP_LEA, 16 - PTR_TAG, 0, R15, trace->ops[op->op1].reg, op->reg);
	emit_imm8(3);
	emit_reg_reg(OP_SAR_CONST, 7, R15);
	emit_reg_reg(OP_MOV_MR, R15, trace->ops[op->op2].reg);
      } else {
	// Must be a fixnum.
        auto c = trace->consts[op->op2 - IR_CONST_BIAS];
	emit_mem_reg(OP_LEA, 16 - PTR_TAG - (c>>3), trace->ops[op->op1].reg, op->reg);
      }
      break;
    }
    case IR_LOAD: {
      // Used for typecheck only
      if (op->reg == REG_NONE) {
	op->reg = get_free_reg(trace, &next_spill, slot, false);
	printf("EMIT LOAD ONLY\n");
      }
      maybe_assign_register(op->op1, trace, slot, &next_spill);
      assert(op->reg != REG_NONE);
      assert(!ir_is_const(op->op1));
      //sassert(!ir_is_const(op->op2));
      assert(trace->ops[op->op1].op == IR_REF ||
             trace->ops[op->op1].op == IR_VREF);
      emit_op_typecheck(op->reg, op->type, snap_labels[cur_snap]);
      emit_mem_reg(OP_MOV_MR, 0, trace->ops[op->op1].reg, op->reg);
      break;
    }
    case IR_ABC: {
      printf("TODO: ABC emit\n");
      break;
    }
    case IR_VREF: {
      // TODO: fuse.
      maybe_assign_register(op->op1, trace, slot, &next_spill);
      maybe_assign_register(op->op2, trace, slot, &next_spill);
      assert(op->reg != REG_NONE);
      assert(!ir_is_const(op->op1));
      if(ir_is_const(op->op2)) {
	// Must be fixnum
        auto c = trace->consts[op->op2 - IR_CONST_BIAS];
	emit_mem_reg(OP_LEA, 16 - PTR_TAG + c, trace->ops[op->op1].reg, op->reg);
      } else {
	emit_mem_reg_sib(OP_LEA, 16 - PTR_TAG, 0, trace->ops[op->op2].reg,
			 trace->ops[op->op1].reg, op->reg);
      }
      break;
    }
    case IR_REF: {
      // TODO: fuse.
      maybe_assign_register(op->op1, trace, slot, &next_spill);
      if (ir_is_const(op->op1)) {
	emit_mem_reg(OP_LEA, op->op2, R15, op->reg);
	auto c = trace->consts[op->op1 - IR_CONST_BIAS];
	auto re = (reloc){emit_offset(), c, RELOC_ABS};
	arrput(trace->relocs, re);
	emit_mov64(R15, c);	
      } else {
	emit_mem_reg(OP_LEA, op->op2, trace->ops[op->op1].reg, op->reg);
      }
      break;
    }
    case IR_STRREF: {
      // TODO: fuse.
      maybe_assign_register(op->op1, trace, slot, &next_spill);
      maybe_assign_register(op->op2, trace, slot, &next_spill);
      assert(!ir_is_const(op->op1));
      if (!ir_is_const(op->op2)) {
	emit_mem_reg_sib(OP_LEA, 16 - PTR_TAG, 0, R15, trace->ops[op->op1].reg, op->reg);
	emit_imm8(3);
	emit_reg_reg(OP_SAR_CONST, 7, R15);
	emit_reg_reg(OP_MOV_MR, R15, trace->ops[op->op2].reg);
      } else {
	// must be fixnum
        auto c = trace->consts[op->op2 - IR_CONST_BIAS] >> 3;
	emit_mem_reg(OP_LEA, 16 - PTR_TAG + c, trace->ops[op->op1].reg, op->reg);
      }
      break;
    }
    case IR_ALLOC: {
      emit_arith_imm(OP_ARITH_ADD, op->reg, op->op2 & TAG_MASK);
      emit_mem_reg(OP_MOV_RM, 0, op->reg, R15);
      emit_mov64(R15, op->type & ~IR_INS_TYPE_GUARD);
      emit_arith_imm(OP_ARITH_SUB, op->reg, op->op1);
      emit_mem_reg(OP_MOV_RM, 0, R15, op->reg);
      emit_mov64(R15, (int64_t)&alloc_ptr);
      // TODO call GC directly?
      emit_jcc32(JGE, snap_labels[cur_snap]);
      emit_reg_reg(OP_CMP, R15, op->reg);
      emit_arith_imm(OP_ARITH_ADD, op->reg, op->op1);
      emit_mem_reg(OP_MOV_MR, 0, op->reg, op->reg);
      emit_mem_reg(OP_MOV_MR, 0, R15, R15);
      emit_mov64(op->reg, (int64_t)&alloc_ptr);
      emit_mov64(R15, (int64_t)&alloc_end);

      break;
    }
    case IR_CARG: {
      break;
    }
    case IR_CALLXS: {
      // Used for typecheck only
      if (op->reg == REG_NONE) {
	op->reg = RAX; // if unused, assign to call result reg.
      }
      preserve_for_call(trace, slot, &next_spill);
      
      // TODO assign to arg1 directly
      if (trace->ops[op->op1].op == IR_CARG) {
	auto cop = &trace->ops[op->op1];
	maybe_assign_register(cop->op1, trace, slot, &next_spill);
	maybe_assign_register(cop->op2, trace, slot, &next_spill);
      } else {
	maybe_assign_register(op->op1, trace, slot, &next_spill);
      }

      // TODO typecheck
      // Restore scheme frame ptr
      // C here is function ptr, const, nonGC
      auto c = trace->consts[op->op2 - IR_CONST_BIAS];
      emit_op_typecheck(op->reg, op->type, snap_labels[cur_snap]);

      emit_reg_reg(OP_MOV, RAX, op->reg);
      emit_reg_reg(OP_MOV, R15, RDI);
      // TODO probably in low mem, no need for mov64
      emit_call_indirect(RAX);
      emit_mov64(RAX, c);
      // args
      if (trace->ops[op->op1].op == IR_CARG) {
	auto cop = &trace->ops[op->op1];
	assert(!ir_is_const(cop->op2));
	if (ir_is_const(cop->op1)) {
	  auto c2 = trace->consts[cop->op1 - IR_CONST_BIAS];
	  auto re = (reloc){emit_offset(), c2, RELOC_ABS};
	  arrput(trace->relocs, re);
	  emit_mov64(RDI, (int64_t)(c2));
	} else {
	  emit_reg_reg(OP_MOV, trace->ops[cop->op1].reg, RDI);
	}
	emit_reg_reg(OP_MOV, trace->ops[cop->op2].reg, RSI);
      } else {
	assert(!ir_is_const(op->op1));
	emit_reg_reg(OP_MOV, trace->ops[op->op1].reg, RDI);
      }
      
      // Save scheme frame ptr
      emit_reg_reg(OP_MOV, RDI, R15);
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
      emit_cmp(JNE, op, trace, snap_labels[cur_snap], slot, &next_spill);
      break;
    }
    case IR_NE: {
      emit_cmp(JE, op, trace, snap_labels[cur_snap], slot, &next_spill);
      break;
    }
    case IR_GE: {
      emit_cmp(JL, op, trace, snap_labels[cur_snap], slot, &next_spill);
      break;
    }
    case IR_LT: {
      emit_cmp(JGE, op, trace, snap_labels[cur_snap], slot, &next_spill);
      break;
    }
    case IR_GT: {
      emit_cmp(JLE, op, trace, snap_labels[cur_snap], slot, &next_spill);
      break;
    }
    case IR_LE: {
      emit_cmp(JG, op, trace, snap_labels[cur_snap], slot, &next_spill);
      break;
    }
    case IR_ADD: {
      emit_arith(OP_ARITH_ADD, OP_ADD, op, trace,
                 snap_labels[cur_snap], slot, &next_spill);
      break;
    }
    case IR_SUB: {
      emit_arith(OP_ARITH_SUB, OP_SUB, op, trace,
                 snap_labels[cur_snap], slot, &next_spill);
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
      // FIXNUM
      auto retadd = (int64_t)(trace->consts[op->op1 - IR_CONST_BIAS]);
      // Constant return address ptr.
      auto b = (int32_t)trace->consts[op->op2 - IR_CONST_BIAS];

      emit_arith_imm(OP_ARITH_SUB, RDI, b);
      emit_jcc32(JNE, snap_labels[cur_snap]);

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
      auto val = find_val_for_slot(op->op1, side_exit, parent);
      if (val >= IR_CONST_BIAS) {
	emit_mov64(op->reg, parent->consts[val - IR_CONST_BIAS]);
      } else {
	auto old_op = &parent->ops[val];
	  // Parallel move direct to register.
	uint32_t from = old_op->reg;
	if (old_op->slot != SLOT_NONE) {
	  from = old_op->slot + REG_NONE;
	}
	uint32_t to = op->reg;
	// TODO if also slot, move to slot.
	if (op->reg == REG_NONE) {
	  to = op->slot + REG_NONE;
	}
	map_insert(&moves, from, to);
	printf("Insert parallel copy %i to %i\n",
	       from, to);
	if (op->slot != SLOT_NONE && op->reg != REG_NONE) {
	  emit_mem_reg(OP_MOV_RM, 0, R15, op->reg);
	  emit_mov64(R15, (int64_t)&spill_slot[op->slot]);
	}
      }
    }
    serialize_parallel_copy(&moves, &res, R15);
    for (int64_t i = (int64_t)res.mp_sz - 1; i >= 0; i--) {
      if (res.mp[i].from >= REG_NONE && res.mp[i].to >= REG_NONE) {
	// Move from spill to spill.
	// Need a second tmp.
	emit_pop(RAX);
	emit_mem_reg(OP_MOV_RM, 0, R15, RAX);
	emit_mov64(R15, (int64_t)&spill_slot[res.mp[i].to - REG_NONE]);
	emit_mem_reg(OP_MOV_MR, 0, R15, RAX);
	emit_mov64(R15, (int64_t)&spill_slot[res.mp[i].from - REG_NONE]);
	emit_push(RAX);
	printf("WARNING slow spill to spill move\n");
      } else if (res.mp[i].from >= REG_NONE) {
	// Move from spill to reg.
	emit_mem_reg(OP_MOV_MR, 0, R15, res.mp[i].to);
	emit_mov64(R15, (int64_t)&spill_slot[res.mp[i].from - REG_NONE]);
      } else if (res.mp[i].to >= REG_NONE) {
	// Move from reg to spill.
	emit_mem_reg(OP_MOV_RM, 0, R15, res.mp[i].from);
	emit_mov64(R15, (int64_t)&spill_slot[res.mp[i].to - REG_NONE]);
      } else {
	emit_reg_reg(OP_MOV, res.mp[i].from, res.mp[i].to);
      }
    }
  }

  auto start = emit_offset();
  if (loop_offset_label != 0U) {
    emit_bind(start, loop_offset_label);
  }
  Func fn = (Func)start;

  trace->fn = fn;
  auto len = (int)(end - start);
  disassemble((const uint8_t *)fn, len);

  if (side_exit != nullptr) {
    emit_bind(start, side_exit->patchpoint);
  }

#ifdef JITDUMP
  perf_map((uint64_t)fn, len, "Trace");
  if (jit_dump_flag) {
    jit_dump(len, (uint64_t)fn, "Trace");
  }
  jit_reader_add(len, (uint64_t)fn, 0, 0, "Trace");
#endif
#ifdef VALGRIND
  VALGRIND_DISCARD_TRANSLATIONS(fn, len);
#endif
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

  /* bcfunc* func = find_func_for_frame(snap->pc); */
  /* assert(func); */
  /*  printf("exit %li from trace %i new pc %li func %s\n", exit, trace->num, */
  /*  snap->pc - &func->code[0], func->name); */
  /*  fflush(stdout); */

   restore_snap(snap, trace, &state, o_frame, o_pc);

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
          auto *otrace = trace_cache_get(INS_D(**o_pc));
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
      auto *otrace = trace_cache_get(INS_D(**o_pc));
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
