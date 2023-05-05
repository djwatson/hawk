#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "asm_x64.h"

const char *reg_names[] = {
  "rax",
  "rbx",
  "rcx",
  "rdx",
  "rsi",
  "rdi",
  "rbp",
  "rsp",
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
    while(cursnap > 0 && trace->snaps[cursnap].ir >= i) {
      //printf("ALLOC FOR SNAP %i\n", cursnap);
      auto& snap = trace->snaps[cursnap];
      for(auto& s : snap.slots) {
	if (!(s.val&IR_CONST_BIAS)) {
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
