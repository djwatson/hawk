#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "ir.h"
#include "asm_x64.h"



void opt_loop(trace_s * trace, int* regs) {
  auto cut = trace->ops.size();
  uint16_t replace[cut];

  {
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op = ir_ins_op::LOOP;
    trace->ops.push_back(ins);
  }

  std::vector<size_t> phis;
  for(size_t i = 0; i < cut; i++) {
    auto& ins = trace->ops[i];
    switch (ins.op) {
    case ir_ins_op::SLOAD: {
      assert(regs[ins.op1] >= 0);
      replace[i] = regs[ins.op1];
      printf("Potential phi: %zu %zu\n", i, trace->ops.size());
      phis.push_back(i);
      break;
    }
    case ir_ins_op::GE:
    case ir_ins_op::ADD:
    case ir_ins_op::SUB: {
      ir_ins copy = ins;
      if (copy.op1 < IR_CONST_BIAS) {
	copy.op1 = replace[copy.op1];
      }
      if (copy.op2 < IR_CONST_BIAS) {
	copy.op2 = replace[copy.op2];
      }
      replace[i] = trace->ops.size();
      trace->ops.push_back(copy);
      break;
    }
    default:{
      printf("Can't loop ir type: %s\n", ir_names[(int)ins.op]);
      exit(-1);
    }
    }
  }
  for(size_t i = 0; i < phis.size(); i++) {
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op = ir_ins_op::PHI;
    ins.op1 = replace[phis[i]];
    ins.op2 = replace[regs[trace->ops[phis[i]].op1]];
    regs[trace->ops[phis[i]].op1] = trace->ops.size();
    trace->ops.push_back(ins);
  }
}
