#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "asm_x64.h"
// TODO only for runtime symbol
#include "bytecode.h"

#include <asmjit/asmjit.h>
#include <capstone/capstone.h>

using namespace asmjit;

void disassemble(const uint8_t* code, int len)
{
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

int get_free_reg(int* slot) {
  for(int i=0; i < regcnt; i++) {
    if (slot[i] == -1) {
      return i;
    }
  }
  printf("ERROR no free reg\n");
  exit(-1);
}

void assign_register(int i, ir_ins& op, int* slot) {
  if (op.reg == REG_NONE) {
    op.reg = get_free_reg(slot);
    slot[op.reg] = i;
    //printf("Assign to op %s reg %s\n", ir_names[(int)op.op], reg_names[op.reg]);
  }
}

void assign_registers(trace_s* trace) {
  int slot[regcnt];
  for(int i = 0; i < regcnt; i++) {
    slot[i] = -1;
  }

  int cursnap = trace->snaps.size()-1;
  for(int i = trace->ops.size()-1; i >= 0; i--) {
    while(cursnap >= 0 && trace->snaps[cursnap].ir >= i) {
      //printf("ALLOC FOR SNAP %i\n", cursnap);
      auto& snap = trace->snaps[cursnap];
      for(auto& s : snap.slots) {
	if (!(s.val&IR_CONST_BIAS)) {
	  //printf("ALLOC FOR SNAP val %i\n", s.val);
	  assign_register(s.val, trace->ops[s.val], slot);
	}
      }
      cursnap--;
    }
    //printf("Assign to %i\n", i);
    
    auto& op = trace->ops[i];
    switch(op.op) {
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
	if (!(op.op1 &IR_CONST_BIAS)) {
	  assign_register(op.op1, trace->ops[op.op1], slot);
	}
	if (!(op.op2 &IR_CONST_BIAS)) {
	  assign_register(op.op2, trace->ops[op.op2], slot);
	}
      }
      break;
    case ir_ins_op::GGET:
    case ir_ins_op::KFIX:
    case ir_ins_op::KFUNC:
      if (op.reg != REG_NONE) {
	if (!(op.op1 &IR_CONST_BIAS)) {
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
  void handleError(Error err, const char* message, BaseEmitter* origin) override {
    printf("AsmJit error: %s\n", message);
  }
};

JitRuntime rt;
void asm_jit(trace_s* trace) {
  // Runtime designed for JIT - it holds relocated functions and controls their lifetime.

  // Holds code and relocation information during code generation.
  CodeHolder code;

  FileLogger logger(stdout);

  // Code holder must be initialized before it can be used. The simples way to initialize
  // it is to use 'Environment' from JIT runtime, which matches the target architecture,
  // operating system, ABI, and other important properties.
  code.init(rt.environment());
  code.setLogger(&logger);
  MyErrorHandler myErrorHandler;  
  code.setErrorHandler(&myErrorHandler);  

  // Emitters can emit code to CodeHolder - let's create 'x86::Assembler', which can emit
  // either 32-bit (x86) or 64-bit (x86_64) code. The following line also attaches the
  // assembler to CodeHolder, which calls 'code.attach(&a)' implicitly.
  x86::Assembler a(&code);

  a.push(x86::rbx);
  a.push(x86::rbp);
  a.push(x86::r12);
  a.push(x86::r13);
  a.push(x86::r14);
  a.push(x86::r15);

  Label l = a.newLabel();
  Label sl = a.newLabel();
  a.bind(sl);

  for(auto&op:trace->ops) {
    switch(op.op) {
    case ir_ins_op::SLOAD: {
      // frame is RDI
      auto reg = ir_to_asmjit[op.reg];
      a.mov(reg, x86::ptr(x86::rdi, op.op1 * 8, 8));
      if (op.type & IR_INS_TYPE_GUARD) {
	a.mov(x86::rbp, reg);
	a.and_(x86::rbp, 0x7);
	a.cmp(x86::rbp, op.type&~IR_INS_TYPE_GUARD);
	a.jne(l);
      }
      break;
    }
    case ir_ins_op::GGET: {
      symbol*sym = (symbol*)trace->consts[op.op1 - IR_CONST_BIAS];
      auto reg = ir_to_asmjit[op.reg];
      a.mov(reg, &sym->val);
      a.mov(reg, x86::ptr(reg, 0, 8));
      if (op.type & IR_INS_TYPE_GUARD) {
	a.mov(x86::rbp, reg);
	a.and_(x86::rbp, 0x7);
	a.cmp(x86::rbp, op.type&~IR_INS_TYPE_GUARD);
	a.jne(l);
      }
      break;
    }
    case ir_ins_op::SUB: {
      auto reg = ir_to_asmjit[op.reg];
      auto reg1 = ir_to_asmjit[trace->ops[op.op1].reg];
      a.mov(reg, reg1);
      if (op.op2 & IR_CONST_BIAS) {
	long v = trace->consts[op.op2 - IR_CONST_BIAS];
	if (v < 32000) {
	  assert(!(op.op1&IR_CONST_BIAS));
	  a.sub(reg, v);
	  a.jo(l);
	} else {
	  assert(false);
	}
      }
      break;
    }
    case ir_ins_op::ADD: {
      assert(!(op.op1 & IR_CONST_BIAS));
      assert(!(op.op2 & IR_CONST_BIAS));
      auto reg = ir_to_asmjit[op.reg];
      auto reg1 = ir_to_asmjit[trace->ops[op.op1].reg];
      a.mov(reg, reg1);
      a.add(reg, ir_to_asmjit[trace->ops[op.op2].reg]);
      a.jo(l);
      break;
    }
    case ir_ins_op::GE: {
      if (op.op2 & IR_CONST_BIAS) {
	long v = trace->consts[op.op2 - IR_CONST_BIAS];
	if (v < 32000) {
	  assert(!(op.op1&IR_CONST_BIAS));
	  a.cmp(ir_to_asmjit[trace->ops[op.op1].reg], v);
	} else {
	  assert(false);
	}
	a.jl(l);
      }
      break;
    }
    case ir_ins_op::EQ: {
      if (op.op2 & IR_CONST_BIAS) {
	long v = trace->consts[op.op2 - IR_CONST_BIAS];
	if (v < 32000) {
	  assert(false);
	} else {
	  assert(!(op.op1&IR_CONST_BIAS));
	  a.mov(x86::rbp, v);
	  a.cmp(ir_to_asmjit[trace->ops[op.op1].reg], x86::rbp);
	}
	a.jne(l);
      }
      break;
    }
    default:
      printf("Can't jit op: %s\n", ir_names[(int)op.op]);
      exit(-1);
    }
  }
  if(trace->link != -1) {
    auto&sn = trace->snaps[trace->snaps.size()-1];
    // TODO frame size check
    for(auto&slot:sn.slots) {
      if (slot.val&IR_CONST_BIAS) {
	auto c = trace->consts[slot.val - IR_CONST_BIAS];
	assert((c&SNAP_FRAME) < 32000);
	a.mov(x86::ptr(x86::rdi, slot.slot * 8, 8), c&~SNAP_FRAME);
      } else {
	a.mov(x86::ptr(x86::rdi, slot.slot * 8, 8), ir_to_asmjit[trace->ops[slot.val].reg]);
      }
    }
    a.jmp(sl);
  }
  a.bind(l);
  a.pop(x86::r15);
  a.pop(x86::r14);
  a.pop(x86::r13);
  a.pop(x86::r12);
  a.pop(x86::rbp);
  a.pop(x86::rbx);
  
  a.ret();

  auto len = a.offset();

  // 'x86::Assembler' is no longer needed from here and can be destroyed or explicitly
  // detached via 'code.detach(&a)' - which detaches an attached emitter from code holder.

  // Now add the generated code to JitRuntime via JitRuntime::add(). This function would
  // copy the code from CodeHolder into memory with executable permission and relocate it.
  Func fn;
  Error err = rt.add(&fn, &code);

  // It's always a good idea to handle errors, especially those returned from the Runtime.
  if (err) {
    printf("AsmJit failed: %s\n", DebugUtils::errorAsString(err));
    exit(-1);
    return;
  }

  printf("--------------MCODE---------------\n");
  disassemble((uint8_t*)fn, len);
  printf("----------------------------------\n");
  trace->fn = fn;
}
