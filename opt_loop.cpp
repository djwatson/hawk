#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "ir.h"
#include "asm_x64.h"



void opt_loop(trace_s * trace, int* regs) {
  auto cut = trace->ops.size();
  uint16_t replace[cut*2+1];

  {
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op = ir_ins_op::LOOP;
    trace->ops.push_back(ins);
  }

  std::vector<size_t> phis;
  unsigned long cur_snap = 0;
  for(size_t i = 0; i < cut + 1; i++) {
    if (i == cut) {
      for(size_t j = 0; j < phis.size(); j++) {
	ir_ins ins;
	ins.reg = REG_NONE;
	ins.op = ir_ins_op::PHI;
	ins.op1 = replace[phis[j]];
	ins.op2 = replace[regs[trace->ops[phis[j]].op1]];
	regs[trace->ops[phis[j]].op1] = trace->ops.size();
	replace[ins.op2] = trace->ops.size();
	replace[ins.op1] = trace->ops.size();
	trace->ops.push_back(ins);
      }
    }
    while((cur_snap < trace->snaps.size()) && (trace->snaps[cur_snap].ir == i)) {
      auto &snap = trace->snaps[cur_snap];
      printf("SNAP %i\n", snap.ir);

      if (cur_snap != 0) {
	snap_s nsnap;
	nsnap.ir = trace->ops.size();
	nsnap.pc = snap.pc;
	nsnap.offset = snap.offset;
	nsnap.exits = 0;
	nsnap.link = -1;
	for(auto&entry : snap.slots) {
	  if(entry.val < IR_CONST_BIAS) {
	    nsnap.slots.push_back({entry.slot, replace[entry.val]});
	  } else {
	    nsnap.slots.push_back(entry);
	  }
	}
      trace->snaps.push_back(nsnap);
      }
      
      cur_snap++;
    }
    if (i == cut) {
      break;
    }
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
    case ir_ins_op::EQ:
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
    case ir_ins_op::GGET: {
      ir_ins copy = ins;
      if (copy.op1 < IR_CONST_BIAS) {
	copy.op1 = replace[copy.op1];
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
}
