#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asm_x64.h"
// TODO only for runtime symbol
#include "bytecode.h"
#include "jitdump.h"
#include "types.h"
// only for tcache
#include "record.h"
#include "vm.h"

#include "emit_x64.h"
#include <capstone/capstone.h>
#include <valgrind/valgrind.h>

#include <map>
std::vector<std::pair<uint64_t, uint64_t>>
serialize_parallel_copy(std::multimap<uint64_t, uint64_t> &moves,
                        uint64_t tmp_reg);

void disassemble(const uint8_t *code, int len) {
  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    return;
  count = cs_disasm(handle, code, len, (uint64_t)code, 0, &insn);
  if (count > 0) {
    size_t j;
    for (j = 0; j < count; j++) {
      printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
             insn[j].op_str);
    }

    cs_free(insn, count);
  } else
    printf("ERROR: Failed to disassemble given code!\n");

  cs_close(&handle);
}

// clang-format off
const char *reg_names[] = {
  "rax",
  "rbx",
  "rcx",
  "rdx",
  "rsi",
  "r8 ", 
  "r9 ", 
  "r10", 
  "r11", 
  "r12", 
  "r13", 
  "r14", 
  "r15",
  "rdi",
  "rbp",
  "rsp",
  "   ",
};

uint8_t ir_to_jit[] = {
  RAX,
  RBX,
  RCX,
  RDX,
  RSI,
  R8,
  R9,
  R10,
  R11,
  R12,
  R13,
  R14,
  R15,
  RDI,
  RBP,
  RSP,
};
// clang-format on

int get_free_reg(int *slot) {
  for (int i = 0; i < regcnt; i++) {
    if (slot[i] == -1) {
      return i;
    }
  }
  printf("ERROR no free reg\n");
  exit(-1);
}

void assign_register(int i, ir_ins &op, int *slot) {
  if (op.reg == REG_NONE) {
    op.reg = get_free_reg(slot);
    slot[op.reg] = i;
    // printf("Assign to op %s reg %s\n", ir_names[(int)op.op],
    // reg_names[op.reg]);
  }
}

void assign_registers(trace_s *trace) {
  int slot[regcnt];
  for (int i = 0; i < regcnt; i++) {
    slot[i] = -1;
  }

  int cursnap = trace->snaps.size() - 1;
  for (int i = trace->ops.size() - 1; i >= 0; i--) {
    while (cursnap >= 0 && trace->snaps[cursnap].ir >= i) {
      // printf("ALLOC FOR SNAP %i\n", cursnap);
      auto &snap = trace->snaps[cursnap];
      for (auto &s : snap.slots) {
        if (!(s.val & IR_CONST_BIAS)) {
          // printf("ALLOC FOR SNAP val %i\n", s.val);
          assign_register(s.val, trace->ops[s.val], slot);
        }
      }
      cursnap--;
    }
    // printf("Assign to %i\n", i);
    auto &op = trace->ops[i];
    
    // free it.
    if (op.reg != REG_NONE) {
      assert(slot[op.reg] == i);
      slot[op.reg] = -1;
    }

    switch (op.op) {
    case ir_ins_op::ARG:
    case ir_ins_op::SLOAD:
      break;
      case ir_ins_op::PHI:
    case ir_ins_op::ADD:
    case ir_ins_op::SUB:
      if (op.reg != REG_NONE) {
      case ir_ins_op::LT:
      case ir_ins_op::GE:
      case ir_ins_op::LE:
      case ir_ins_op::GT:
      case ir_ins_op::EQ:
      case ir_ins_op::NE:
        if (!(op.op1 & IR_CONST_BIAS)) {
          assign_register(op.op1, trace->ops[op.op1], slot);
        }
        if (!(op.op2 & IR_CONST_BIAS)) {
          assign_register(op.op2, trace->ops[op.op2], slot);
        }
      }
      if (op.op == ir_ins_op::PHI) {
	assert(trace->ops[op.op1].reg == op.reg);
      }
      break;
    case ir_ins_op::GGET:
    case ir_ins_op::KFIX:
    case ir_ins_op::KFUNC:
      if (op.reg != REG_NONE) {
        if (!(op.op1 & IR_CONST_BIAS)) {
          assign_register(op.op1, trace->ops[op.op1], slot);
        }
      }
      break;
    default:
      break;
    }
  }
}

// class MyErrorHandler : public ErrorHandler {
// public:
//   void handleError(Error err, const char *message,
//                    BaseEmitter *origin) override {
//     printf("AsmJit error: %s\n", message);
//     assert(false);
//   }
// };


struct exit_state {
  long regs[regcnt];
  long trace;
  long snap;
};

extern "C" unsigned long jit_entry_stub(long **o_frame, unsigned int **o_pc, Func fptr, long *regs);
extern "C" unsigned long jit_exit_stub();

static exit_state exit_state_save;

extern "C" void exit_stub_frame_restore(exit_state* state) {
  memcpy(&exit_state_save, state, sizeof(exit_state));
}

void restore_snap(snap_s* snap, trace_s* trace, exit_state *state, long **o_frame, unsigned int **o_pc) {
  for (auto&slot : snap->slots) {
    if (slot.val & IR_CONST_BIAS) {
      auto c = trace->consts[slot.val - IR_CONST_BIAS];
      (*o_frame)[slot.slot] = c & ~SNAP_FRAME;
    } else {
      (*o_frame)[slot.slot] = state->regs[trace->ops[slot.val].reg];
    }
  }
  
  (*o_pc) = snap->pc;
  (*o_frame) += snap->offset;
}

uint16_t find_reg_for_slot(int slot, snap_s* snap, trace_s* trace) {
  for(auto& s:snap->slots) {
    if (s.slot == slot) {
      if (s.val >= IR_CONST_BIAS) {
	return s.val;
      }
      return trace->ops[s.val].reg;
    }
  }
  assert(false);
}

void emit_snap(int snap, trace_s *trace, bool all) {
  printf("EMITSNAP: all %i\n", all);
  auto &sn = trace->snaps[snap];
  int last_ret = -1;
  for(int i = sn.ir; i >= 0; i--) {
    if (trace->ops[i].op == ir_ins_op::RET) {
      last_ret = i;
      break;
    }
  }
  // TODO frame size check
  for (auto &slot : sn.slots) {
    emit_check();
    // if (!all && (slot.slot >= sn.offset)) {
    //   break;
    // }
    if (slot.val & IR_CONST_BIAS) {
      auto c = trace->consts[slot.val - IR_CONST_BIAS];
      // assert((c&SNAP_FRAME) < 32000);
      //printf("MOV %lx\n", c & ~SNAP_FRAME);
      emit_mem_reg(OP_MOV_RM, slot.slot * 8, RDI, R15);
      emit_mov64(R15, c & ~SNAP_FRAME);
    } else {
      auto&op = trace->ops[slot.val];
      // TODO RET check, can't emit past RETS
      if (slot.val > last_ret &&
	  (op.op == ir_ins_op::SLOAD &&
	   (op.type & IR_INS_TYPE_GUARD)) && 
	  op.op1 == slot.slot && slot.slot < sn.offset) {
	printf("DROPPING emit snap of slot %i\n", slot.slot);
	// nothing
      } else {
	emit_mem_reg(OP_MOV_RM, slot.slot * 8, RDI, ir_to_jit[op.reg]);
      }
    }
  }
  // TODO check stack size
}

void emit_arith(enum ARITH_CODES arith_code, enum OPCODES op_code, ir_ins&op, trace_s *trace, int32_t offset) {
  emit_jcc32(JO, offset);
      
  assert(!(op.op1 & IR_CONST_BIAS));
  auto reg = ir_to_jit[op.reg];
  auto reg1 = ir_to_jit[trace->ops[op.op1].reg];
  if (op.op2 & IR_CONST_BIAS) {
    long v = trace->consts[op.op2 - IR_CONST_BIAS];
    if ((long)((int32_t)v) == v) {
      emit_arith_imm(arith_code, reg, v);
    } else {
      assert(false);
    }
  } else {
    emit_reg_reg(op_code, ir_to_jit[trace->ops[op.op2].reg], reg);
  }
  if (reg != reg1) {
    emit_reg_reg(OP_MOV, reg1, reg);
  }
}

void emit_cmp(enum jcc_cond cmp, ir_ins& op, trace_s *trace, int32_t offset) {
  emit_jcc32(cmp, offset);
  assert(!(op.op1 & IR_CONST_BIAS));
  if (op.op2 & IR_CONST_BIAS) {
    long v = trace->consts[op.op2 - IR_CONST_BIAS];
    if ((long)((int32_t)v) == v) {
      emit_arith_imm(OP_ARITH_CMP, ir_to_jit[trace->ops[op.op1].reg], v);
    } else {
      emit_reg_reg(OP_CMP, ir_to_jit[trace->ops[op.op1].reg], R15);
      emit_mov64(R15, v);
    }
  } else {
    auto reg1 = ir_to_jit[trace->ops[op.op1].reg];
    auto reg2 = ir_to_jit[trace->ops[op.op2].reg];
    emit_reg_reg(OP_CMP, reg1, reg2);
  }
}

void emit_op_typecheck(uint8_t reg, uint8_t type, int32_t offset) {
  if (type & IR_INS_TYPE_GUARD) {
    emit_jcc32(JNE, offset);
    if ((type &~IR_INS_TYPE_GUARD ) == 0) {
      emit_op_imm32(OP_TEST_IMM, 0, R15, 0x7);
    } else {
      emit_cmp_reg_imm32(R15, type & ~IR_INS_TYPE_GUARD);
      emit_op_imm32(OP_AND_IMM, 4, R15, 0x7);
    }
    emit_reg_reg(OP_MOV, reg, R15);
  }
}

void asm_jit(trace_s *trace, snap_s *side_exit, trace_s* parent) {
  emit_init();

  uint64_t snap_labels[trace->snaps.size()-1];

  auto end = emit_offset();

  emit_check();
  emit_jmp_abs(R15);
  emit_mov64(R15, int64_t(jit_exit_stub));
  emit_check();
  emit_push(R15);
  emit_mov64(R15, (int64_t)trace);
  emit_push(R15);
  
  auto exit_label = emit_offset();


  for (long i = trace->snaps.size() - 1; i >= 0; i--) {
    emit_check();
    // Funny embed here, so we can patch later.
    //emit_jmp_rel(exit_label - emit_offset());
    trace->snaps[i].patchpoint = emit_offset();
    emit_jmp32(exit_label-emit_offset());
    emit_mov64(R15, i);
    snap_labels[i] = emit_offset();
  }

  uint64_t loop_offset_label = 0;

  if (trace->link != -1) {
    auto otrace = trace_cache_get(trace->link);
    emit_check();
    
    if (otrace != trace) {
      emit_jmp_abs(R15);
      emit_mov64(R15, uint64_t(otrace->fn));
    } else {
      // Patched at top.
      loop_offset_label = emit_offset();
      emit_jmp32(0);
    }

    emit_check();
    auto &last_snap = trace->snaps[trace->snaps.size()-1];
    if (last_snap.offset) {
      emit_arith_imm(OP_ARITH_ADD, RDI, last_snap.offset * 8);
    }
    
//     // Parallel move if there are args
//     {
//       std::multimap<uint64_t, uint64_t> moves;
//       std::vector<std::pair<int, uint16_t>> consts;
//       for (size_t op_cnt2 = 0; op_cnt2 < otrace->ops.size(); op_cnt2++) {
// 	auto&op = otrace->ops[op_cnt2];
// 	// TODO parent type
// 	if (op.op != ir_ins_op::ARG) {
// 	  break;
// 	}
// 	auto oldreg = find_reg_for_slot(op.op1 + last_snap.offset, &last_snap, trace);
// 	if (oldreg >= IR_CONST_BIAS) {
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
    emit_snap(trace->snaps.size() - 1, trace, (INS_OP(otrace->startpc)!=FUNC));
  } else {
    // No link, jump back to interpreter loop.
    emit_check();
    emit_jmp32(exit_label - emit_offset());
    emit_mov64(R15, trace->snaps.size()-1);
  }

  long cur_snap = trace->snaps.size()-1;
  long op_cnt = trace->ops.size()-1;
  for(; op_cnt >= 0; op_cnt--) {
    while(trace->snaps[cur_snap].ir > op_cnt) {
      cur_snap--;
    }
    auto&op = trace->ops[op_cnt];
    emit_check();
    switch(op.op) {
    case ir_ins_op::SLOAD: {
      // frame pointer in RDI
      auto reg = ir_to_jit[op.reg];
      emit_op_typecheck(reg, op.type, snap_labels[cur_snap] - emit_offset());
      if (!(op.type & IR_INS_TYPE_GUARD)) {
	goto done;
      }
      emit_mem_reg(OP_MOV_MR, op.op1 * 8, RDI, reg);
      break;
    } 
    case ir_ins_op::GGET: {
      symbol *sym = (symbol *)trace->consts[op.op1 - IR_CONST_BIAS];
      auto reg = ir_to_jit[op.reg];
      emit_op_typecheck(reg, op.type, snap_labels[cur_snap] - emit_offset());
      emit_mem_reg(OP_MOV_MR, 0, reg, reg);
      emit_mov64(reg, (int64_t)&sym->val);
      break;
    }
//     case ir_ins_op::CLT: {
//       assert(!(op.op1 & IR_CONST_BIAS));
//       auto reg = ir_to_asmjit[op.reg];
//       // beware of colision with one of the other regs
//       auto reg1 = ir_to_asmjit[trace->ops[op.op1].reg];
//       if (op.op2 & IR_CONST_BIAS) {
//         long v = trace->consts[op.op2 - IR_CONST_BIAS];
//         assert(v < 32000);
//         a.cmp(reg1, v);
//       } else {
//         auto reg2 = ir_to_asmjit[trace->ops[op.op2].reg];
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
    case ir_ins_op::EQ: {
      emit_cmp(JNE, op, trace, snap_labels[cur_snap] - emit_offset());
      break;
    }
    case ir_ins_op::NE: {
      emit_cmp(JE, op, trace, snap_labels[cur_snap] - emit_offset());
      break;
    }
    case ir_ins_op::GE: {
      emit_cmp(JL, op, trace, snap_labels[cur_snap] - emit_offset());
      break;
    }
    case ir_ins_op::LT: {
      emit_cmp(JGE, op, trace, snap_labels[cur_snap] - emit_offset());
      break;
    }
    case ir_ins_op::ADD: {
      emit_arith(OP_ARITH_ADD, OP_ADD, op, trace, snap_labels[cur_snap] - emit_offset());
      break;
    }
    case ir_ins_op::SUB: {
      emit_arith(OP_ARITH_SUB, OP_SUB, op, trace, snap_labels[cur_snap] - emit_offset());
      break;
    }
//     case ir_ins_op::LOOP: {
//       printf("------------LOOP-------------\n");
//       a.bind(loop_label);
//       use_loop = true;
//       break;
//     }
//     case ir_ins_op::PHI: {
//       auto reg1 = ir_to_asmjit[trace->ops[op.op1].reg];
//       auto reg2 = ir_to_asmjit[trace->ops[op.op2].reg];
//       if(reg1 != reg2) {
// 	a.mov(reg1, reg2);
//       }
//       break;
//     }
    case ir_ins_op::RET: {
      auto retadd = trace->consts[op.op1 - IR_CONST_BIAS] - SNAP_FRAME;
      auto b = trace->consts[op.op2 - IR_CONST_BIAS];

      emit_arith_imm(OP_ARITH_SUB, RDI, b);
      emit_jcc32(JNE, snap_labels[cur_snap] - emit_offset());

      emit_mem_reg(OP_CMP, -8, RDI, R15);

      emit_mov64(R15, retadd);
      
      
      break;
    }
    default: {
      printf("Can't jit op: %s\n", ir_names[(int)op.op]);
      exit(-1);
    }
    }
  }

 done:
  // TODO parent loads should have separate TAG
  // Parallel move if there are args
  {
    std::multimap<uint64_t, uint64_t> moves;
    std::vector<std::pair<int, uint16_t>> consts;
    for (; op_cnt >= 0; op_cnt--) {
      auto&op = trace->ops[op_cnt];
      moves.insert(std::make_pair(find_reg_for_slot(op.op1, side_exit, parent), op.reg));
    }
    auto res = serialize_parallel_copy(moves, 12 /* r15 */);
    printf("Parellel copy:\n");
    for(auto&mov: moves) {
      printf(" %li to %li\n", mov.first, mov.second);
    }
    printf("----------------\n");
    for(auto&c : consts) {
      auto con = trace->consts[c.second - IR_CONST_BIAS];
      emit_mov64(ir_to_jit[c.first], con & ~SNAP_FRAME);
    }
    for(auto r = res.rbegin(); r != res.rend(); r++) {
      // TODO reverse
      emit_reg_reg(OP_MOV, ir_to_jit[r->first], ir_to_jit[r->second]);
    }
  }

  auto start = emit_offset();
  if (loop_offset_label) {
    emit_bind(start, loop_offset_label);
  }
  Func fn = (Func)start;

  trace->fn = fn;
  auto len = end-start;
  disassemble((const uint8_t*)fn, len);

  if (side_exit) {
    emit_bind(start, side_exit->patchpoint);
  }
  
  perf_map(uint64_t(fn), len, std::string("Trace"));
  jit_dump(len, uint64_t(fn), std::string("Trace"));
  jit_reader_add(len, uint64_t(fn), 0, 0, std::string("Trace"));
  VALGRIND_DISCARD_TRANSLATIONS(fn, len);
}

extern unsigned int *patchpc;
extern unsigned int patchold;
int jit_run(unsigned int tnum, unsigned int **o_pc, long **o_frame,
            long *frame_top) {
  auto trace = trace_cache_get(tnum);

  for(auto&op : trace->ops) {
    if (op.op != ir_ins_op::ARG) {
      break;
    }
    exit_state_save.regs[op.reg] = (*o_frame)[op.op1];
  }

  //printf("FN start %i\n", tnum);
  auto exit = jit_entry_stub(o_frame, o_pc, trace->fn, exit_state_save.regs);
  trace = (trace_s *)exit_state_save.trace;
  exit = exit_state_save.snap;
  auto snap = &trace->snaps[exit];

  restore_snap(snap, trace, &exit_state_save, o_frame, o_pc);
  // auto func = find_func_for_frame(snap->pc);
  // assert(func);
  //  printf("exit %li from trace %i new pc %li func %s\n", exit, trace->num, snap->pc - &func->code[0], func->name.c_str());

  if (exit != trace->snaps.size() - 1) {
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
          auto otrace = trace_cache_get(INS_B(**o_pc));
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
	auto otrace = trace_cache_get(INS_B(**o_pc));
      if (INS_OP(otrace->startpc) == LOOP) {
	(*o_pc)++;
      } else {
	*o_pc = &otrace->startpc;
      }
      //printf("Exit to loop\n");
      return 0;
    }
  }

  // printf("FN return\n");
  return 0;
}
