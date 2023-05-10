#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "asm_x64.h"
// TODO only for runtime symbol
#include "bytecode.h"
#include "jitdump.h"
// only for tcache
#include "record.h"

#include <asmjit/asmjit.h>
#include <capstone/capstone.h>
#include <valgrind/valgrind.h>

using namespace asmjit;

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

x86::Gp ir_to_asmjit[] = {
  x86::rax,
  x86::rbx,
  x86::rcx,
  x86::rdx,
  x86::rsi,
  x86::r8,
  x86::r9,
  x86::r10,
  x86::r11,
  x86::r12,
  x86::r13,
  x86::r14,
  x86::r15,
  x86::rdi,
  x86::rbp,
  x86::rsp,
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
    switch (op.op) {
    case ir_ins_op::SLOAD:
      break;
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
    // free it.
    if (op.reg != REG_NONE) {
      assert(slot[op.reg] == i);
      slot[op.reg] = -1;
    }
  }
}

class MyErrorHandler : public ErrorHandler {
public:
  void handleError(Error err, const char *message,
                   BaseEmitter *origin) override {
    printf("AsmJit error: %s\n", message);
  }
};

void emit_snap(x86::Assembler &a, int snap, trace_s *trace) {
  auto &sn = trace->snaps[snap];
  // TODO frame size check
  for (auto &slot : sn.slots) {
    if (slot.val & IR_CONST_BIAS) {
      auto c = trace->consts[slot.val - IR_CONST_BIAS];
      // assert((c&SNAP_FRAME) < 32000);
      printf("MOV %lx\n", c & ~SNAP_FRAME);
      a.mov(x86::r15, c & ~SNAP_FRAME);
      a.mov(x86::ptr(x86::rdi, slot.slot * 8, 8), x86::r15);
    } else {
      a.mov(x86::ptr(x86::rdi, slot.slot * 8, 8),
            ir_to_asmjit[trace->ops[slot.val].reg]);
    }
  }
  // Pump offset
  // TODO check stack size
  a.add(x86::rdi, sn.offset * 8);
  // Store frame
  a.mov(x86::r15, x86::ptr(x86::rsp, 8, 8));
  a.mov(x86::ptr(x86::r15, 0, 8), x86::rdi);
  // Adjust pc
  a.mov(x86::r15, x86::ptr(x86::rsp, 0, 8));
  // TODO
  a.mov(x86::ptr(x86::r15, 0, 8), snap);
}

JitRuntime rt;
void asm_jit(trace_s *trace, snap_s *side_exit) {
  // Runtime designed for JIT - it holds relocated functions and controls their
  // lifetime.

  // Holds code and relocation information during code generation.
  CodeHolder code;

  FileLogger logger(stdout);

  // Code holder must be initialized before it can be used. The simples way to
  // initialize it is to use 'Environment' from JIT runtime, which matches the
  // target architecture, operating system, ABI, and other important properties.
  code.init(rt.environment());
  code.setLogger(&logger);
  MyErrorHandler myErrorHandler;
  code.setErrorHandler(&myErrorHandler);

  // Emitters can emit code to CodeHolder - let's create 'x86::Assembler', which
  // can emit either 32-bit (x86) or 64-bit (x86_64) code. The following line
  // also attaches the assembler to CodeHolder, which calls 'code.attach(&a)'
  // implicitly.
  x86::Assembler a(&code);
  a.addValidationOptions(
      BaseAssembler::ValidationOptions::kValidationOptionAssembler |
      BaseAssembler::ValidationOptions::kValidationOptionIntermediate);

  if (!side_exit) {
    a.push(x86::rbp);
    a.mov(x86::rbp, x86::rsp);
    a.push(x86::rbx);
    a.push(x86::r12);
    a.push(x86::r13);
    a.push(x86::r14);
    a.push(x86::r15);
    a.push(x86::rdi);
    a.push(x86::rsi);
    a.mov(x86::rdi, x86::ptr(x86::rdi, 0, 8));
  } else {
    a.sub(x86::rdi, side_exit->offset * 8);
  }

  Label sl = a.newLabel();
  Label exit_label = a.newLabel();
  a.bind(sl);
  Label snap_labels[trace->snaps.size() - 1];
  Label snap_labels_patch[trace->snaps.size() - 1];
  for (unsigned long i = 0; i < trace->snaps.size() - 1; i++) {
    snap_labels[i] = a.newLabel();
    snap_labels_patch[i] = a.newLabel();
  }
  long cur_snap = 0;

  long op_cnt = 0;
  for (auto &op : trace->ops) {
    while (trace->snaps[cur_snap + 1].ir <= op_cnt) {
      cur_snap++;
    }
    op_cnt++;
    switch (op.op) {
    case ir_ins_op::SLOAD: {
      // frame is RDI
      auto reg = ir_to_asmjit[op.reg];
      a.mov(reg, x86::ptr(x86::rdi, op.op1 * 8, 8));
      if (op.type & IR_INS_TYPE_GUARD) {
        a.mov(x86::r15, reg);
        a.and_(x86::r15, 0x7);
        a.cmp(x86::r15, op.type & ~IR_INS_TYPE_GUARD);
        a.jne(snap_labels[cur_snap]);
      }
      break;
    }
    case ir_ins_op::GGET: {
      symbol *sym = (symbol *)trace->consts[op.op1 - IR_CONST_BIAS];
      auto reg = ir_to_asmjit[op.reg];
      a.mov(reg, &sym->val);
      a.mov(reg, x86::ptr(reg, 0, 8));
      if (op.type & IR_INS_TYPE_GUARD) {
        a.mov(x86::r15, reg);
        a.and_(x86::r15, 0x7);
        a.cmp(x86::r15, op.type & ~IR_INS_TYPE_GUARD);
        a.jne(snap_labels[cur_snap]);
      }
      break;
    }
    case ir_ins_op::SUB: {
      auto reg = ir_to_asmjit[op.reg];
      auto reg1 = ir_to_asmjit[trace->ops[op.op1].reg];
      a.mov(reg, reg1);
      assert(!(op.op1 & IR_CONST_BIAS));
      if (op.op2 & IR_CONST_BIAS) {
        long v = trace->consts[op.op2 - IR_CONST_BIAS];
        if (v < 32000) {
          a.sub(reg, v);
        } else {
          assert(false);
        }
      } else {
	auto reg2 = ir_to_asmjit[trace->ops[op.op2].reg];
	a.sub(reg, reg2);
      }
      a.jo(snap_labels[cur_snap]);
      break;
    }
    case ir_ins_op::ADD: {
      assert(!(op.op1 & IR_CONST_BIAS));
      auto reg = ir_to_asmjit[op.reg];
      auto reg1 = ir_to_asmjit[trace->ops[op.op1].reg];
      a.mov(reg, reg1);
      if (op.op2 & IR_CONST_BIAS) {
        long v = trace->consts[op.op2 - IR_CONST_BIAS];
        if (v < 32000) {
          a.add(reg, v);
        } else {
          assert(false);
        }
      } else {
        a.add(reg, ir_to_asmjit[trace->ops[op.op2].reg]);
      }
      a.jo(snap_labels[cur_snap]);
      break;
    }
    case ir_ins_op::GE: {
      assert(!(op.op1 & IR_CONST_BIAS));
      if (op.op2 & IR_CONST_BIAS) {
        long v = trace->consts[op.op2 - IR_CONST_BIAS];
        if (v < 32000) {
          a.cmp(ir_to_asmjit[trace->ops[op.op1].reg], v);
        } else {
          assert(false);
        }
      } else {
        auto reg1 = ir_to_asmjit[trace->ops[op.op1].reg];
        auto reg2 = ir_to_asmjit[trace->ops[op.op2].reg];
        a.cmp(reg1, reg2);
      }
      a.jl(snap_labels[cur_snap]);
      break;
    }
    case ir_ins_op::LT: {
      assert(!(op.op1 & IR_CONST_BIAS));
      if (op.op2 & IR_CONST_BIAS) {
        long v = trace->consts[op.op2 - IR_CONST_BIAS];
        if (v < 32000) {
          a.cmp(ir_to_asmjit[trace->ops[op.op1].reg], v);
        } else {
          assert(false);
        }
      } else {
        auto reg1 = ir_to_asmjit[trace->ops[op.op1].reg];
        auto reg2 = ir_to_asmjit[trace->ops[op.op2].reg];
        a.cmp(reg1, reg2);
      }
      a.jge(snap_labels[cur_snap]);
      break;
    }
    case ir_ins_op::NE: {
      if (op.op2 & IR_CONST_BIAS) {
	// TODO move to an opt pass
	if (op.op1 & IR_CONST_BIAS) {
	  break;
	}
        long v = trace->consts[op.op2 - IR_CONST_BIAS];
        if (v < 32000) {
          assert(!(op.op1 & IR_CONST_BIAS));
          a.mov(x86::r15, v);
          a.cmp(ir_to_asmjit[trace->ops[op.op1].reg], x86::r15);
        } else {
          assert(false);
        }
      } else {
        assert(false);
      }
      a.je(snap_labels[cur_snap]);
      break;
    }
    case ir_ins_op::EQ: {
      assert(!(op.op1 & IR_CONST_BIAS));
      if (op.op2 & IR_CONST_BIAS) {
        long v = trace->consts[op.op2 - IR_CONST_BIAS];
        if (v < 32000) {
          a.cmp(ir_to_asmjit[trace->ops[op.op1].reg], v);
        } else {
          a.mov(x86::r15, v);
          a.cmp(ir_to_asmjit[trace->ops[op.op1].reg], x86::r15);
        }
        a.jne(snap_labels[cur_snap]);
      } else {
        assert(false);
      }
      break;
    }
    case ir_ins_op::RET: {
      auto retadd = trace->consts[op.op1 - IR_CONST_BIAS] - SNAP_FRAME;
      auto b = trace->consts[op.op2 - IR_CONST_BIAS];
      a.mov(x86::r15, retadd);
      a.cmp(x86::r15, x86::ptr(x86::rdi, -1 * 8, 8));
      a.jne(snap_labels[cur_snap]);
      a.sub(x86::rdi, b);
      break;
    }
    default:
      printf("Can't jit op: %s\n", ir_names[(int)op.op]);
      exit(-1);
    }
  }
  emit_snap(a, trace->snaps.size() - 1, trace);
  if (trace->link != -1) {
    auto otrace = trace_cache_get(trace->link);
    if (otrace != trace) {
      a.mov(x86::r15, uint64_t(otrace->fn) + 0x12);
      a.jmp(x86::r15);
    } else {
      // TODO removing this breaks ack
      a.jmp(sl);
    }
    a.jmp(exit_label);
  } else {
    a.jmp(exit_label);
  }
  for (unsigned long i = 0; i < trace->snaps.size() - 1; i++) {
    a.bind(snap_labels[i]);
    emit_snap(a, i, trace);
    // Funny embed here, so we can patch later.
    a.jmp(x86::ptr(snap_labels_patch[i]));
  }

  a.bind(exit_label);

  // Pop saved &pc
  a.pop(x86::r15);
  // Pop saved &frame
  a.pop(x86::r15);
  // restore callee-save
  a.pop(x86::r15);
  a.pop(x86::r14);
  a.pop(x86::r13);
  a.pop(x86::r12);
  a.pop(x86::rbx);
  a.pop(x86::rbp);
  a.mov(x86::rax, trace);

  a.ret();
  for (unsigned long i = 0; i < trace->snaps.size() - 1; i++) {
    a.bind(snap_labels_patch[i]);
    trace->snaps[i].patchpoint = a.offset();
    a.embedLabel(exit_label, 8);
  }

  auto len = a.offset();

  // 'x86::Assembler' is no longer needed from here and can be destroyed or
  // explicitly detached via 'code.detach(&a)' - which detaches an attached
  // emitter from code holder.

  // Now add the generated code to JitRuntime via JitRuntime::add(). This
  // function would copy the code from CodeHolder into memory with executable
  // permission and relocate it.
  Func fn;
  Error err = rt.add(&fn, &code);

  // It's always a good idea to handle errors, especially those returned from
  // the Runtime.
  if (err) {
    printf("AsmJit failed: %s\n", DebugUtils::errorAsString(err));
    exit(-1);
    return;
  }

  for (unsigned long i = 0; i < trace->snaps.size() - 1; i++) {
    trace->snaps[i].patchpoint += uint64_t(fn);
  }
  printf("--------------MCODE---------------\n");
  disassemble((uint8_t *)fn, len);
  printf("----------------------------------\n");
  trace->fn = fn;
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

  // printf("FN start %i\n", tnum);
  long exit = trace->fn(o_frame, o_pc);
  // TODO exit holds new trace, o_pc holds exit num
  // printf("Exit %i %lx %lx\n", (*o_pc), exit, trace);
  trace = (trace_s *)exit;
  exit = (long)(*o_pc);
  // printf("From trace %i\n", trace->num);
  bcfunc *func = (bcfunc *)((*o_frame)[-1] - 5);
  // TODO exit is probably wrong if side trace
  auto snap = &trace->snaps[exit];
  // printf("exit %i from trace %i new pc %i func %lx\n", exit, trace->num,
  // snap->pc, func);
  (*o_pc) = snap->pc;

  if (exit != trace->snaps.size() - 1) {
    if (snap->exits < 10) {
      snap->exits++;
    } else {
      if (snap->exits < 14) {
        snap->exits++;
        printf("Hot snap %i\n", exit);
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
      auto otrace = trace_cache_get(INS_B(**o_pc));
      *o_pc = &otrace->startpc;
      printf("Exit to loop\n");
      return 0;
    }
  }

  // printf("FN return\n");
  return 0;
}
