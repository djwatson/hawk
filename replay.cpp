#include "record.h"
// TODO for runtime symbol
#include "bytecode.h"

#include <stdio.h>
#include <stdlib.h>

// Simple replay to test recording before we write a jit.

long get_val_or_const(std::vector<long>& res, uint16_t v, std::vector<long>& consts) {
  if(v&IR_CONST_BIAS) {
    return consts[v-IR_CONST_BIAS];
  }
  return res[v];
}

snap_s* find_snap_for_pc(unsigned int pc, trace_s* trace) {
  snap_s* res = NULL;
  for(auto&s:trace->snaps) {
    if (s.ir <= pc) {
      res = &s;
    }
  }
  return res;
}

extern long *stack;
void snap_restore(std::vector<long>&res, unsigned int **o_pc, long **o_frame, snap_s* snap, trace_s* trace) {
  for(auto&slot:snap->slots) {
    if (slot.val & IR_CONST_BIAS) {
      auto c = trace->consts[slot.val - IR_CONST_BIAS];
      if (c&SNAP_FRAME) {
	(*o_frame)[slot.slot] = c&~SNAP_FRAME;
      } else {
	(*o_frame)[slot.slot] = c;
      }
    } else {
      printf("Snap restore slot %i val %li ptr %lx\n", slot.slot, res[slot.val], &(*o_frame)[slot.slot]);
      (*o_frame)[slot.slot] = res[slot.val];
    }
  }
  *o_frame = *o_frame + snap->offset;
  bcfunc* func = (bcfunc*)((*o_frame)[-1]-5);
  *o_pc = &func->code[snap->pc];
  printf("PC is now %i %s\n", snap->pc, ins_names[INS_OP(**o_pc)]);
  printf("Stack is now %li func is %lx\n", *o_frame-stack, func);
}

int record_run(unsigned int tnum, unsigned int **o_pc, long **o_frame,
	       long *frame_top);
int replay_abort(unsigned int ir_pc, trace_s* trace, std::vector<long>& res, unsigned int **o_pc, long **o_frame) {
  printf("Replay failed guard, abort ir pc %i\n", ir_pc);
  auto snap = find_snap_for_pc(ir_pc, trace);
  snap_restore(res, o_pc, o_frame, snap, trace);
  if (snap->link != -1) {
    // Don't adjust stack frame for links
    // TODO: infact, in generated code snap_restore will be not done at all when jumping to side trace.
    *o_frame = *o_frame - snap->offset; 
  bcfunc* func = (bcfunc*)((*o_frame)[-1]-5);
    printf("Stack is now %li func is %lx\n", *o_frame-stack, func);
    printf("Snap link %i\n", snap->link);
    return record_run(snap->link, o_pc, o_frame, NULL);

  }

  if (snap->exits < 10) {
    snap->exits++;
  } else {
    printf("Hot snap %i\n", ir_pc);
    record_side(trace, snap);
    return 1;
  }
  
  return 0;
}

extern long on_trace;

int record_run(unsigned int tnum, unsigned int **o_pc, long **o_frame,
                long *frame_top) {
 again:
  auto trace = trace_cache_get(tnum);

  unsigned int pc = 0;
  std::vector<long> res;
  res.resize(trace->ops.size());

  long* frame = *o_frame;

  while(pc < trace->ops.size()) {
    on_trace++;
    auto& ins = trace->ops[pc];
    printf("Replay %s %i %i\n", ir_names[(int)ins.op], ins.op1, ins.op2);
    for(int i = 0; i < pc; i++) {
      printf("%i: %lx ", i, res[i]);
    }
    printf("\n");
    switch(ins.op) {
    case ir_ins_op::SLOAD: {
      res[pc] = frame[ins.op1];
      // TODO guard on type
      pc++;
      break;
    }
    case ir_ins_op::LT: {
      auto a = get_val_or_const(res, ins.op1, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      //printf("LT %li %li\n", a>>3, b>>3);
      if (a >= b) { 
	return replay_abort(pc, trace, res, o_pc, o_frame);
      }
      pc++;
      break;
    }
    case ir_ins_op::GE: {
      auto a = get_val_or_const(res, ins.op1, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      //printf("GE %li %li\n", a>>3, b>>3);
      if (a < b) { 
	return replay_abort(pc, trace, res, o_pc, o_frame);
      }
      pc++;
      break;
    }
    case ir_ins_op::NE: {
      auto a = get_val_or_const(res, ins.op1, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      //printf("EQ %li %li\n", a, b);
      if (a == b) {
	return replay_abort(pc, trace, res, o_pc, o_frame);
      }
      pc++;
      break;
    }
    case ir_ins_op::EQ: {
      auto a = get_val_or_const(res, ins.op1, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      //printf("EQ %li %li\n", a, b);
      if (a != b) {
	return replay_abort(pc, trace, res, o_pc, o_frame);
      }
      pc++;
      break;
    }
    case ir_ins_op::GGET: {
      symbol* a = (symbol*)get_val_or_const(res, ins.op1, trace->consts);
      //printf("GGET %s %lx\n", a->name.c_str(), a->val);
      res[pc] = a->val;
      // TODO guard type
      pc++;
      break;
    }
    case ir_ins_op::SUB: {
      auto a = get_val_or_const(res, ins.op1, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      printf("SUB %li %li\n", a>>3, b>>3);
      if (__builtin_sub_overflow(a, b, &res[pc])) {
	return replay_abort(pc, trace, res, o_pc, o_frame);
      }
      pc++;
      break;
    }
    case ir_ins_op::ADD: {
      auto a = get_val_or_const(res, ins.op1, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      //printf("ADD %li %li\n", a>>3, b>>3);
      if (__builtin_add_overflow(a, b, &res[pc])) {
	return replay_abort(pc, trace, res, o_pc, o_frame);
      }
      pc++;
      break;
    }
    default: {
      printf("Unknown replay op: %s\n", ir_names[(int)ins.op]);
      exit(-1);
    }
    }
  }
  printf("At end of trace\n");
  bcfunc* func = (bcfunc*)((*o_frame)[-1]-5);
    printf("Stack is now %li func is %lx\n", *o_frame-stack, func);
  auto& snap = trace->snaps[trace->snaps.size()-1];
  snap_restore(res, o_pc, o_frame, &snap, trace);
  printf("Frame %li %li %li %li\n",
	 (*o_frame)[0],
	 (*o_frame)[1],
	 (*o_frame)[2],
	 (*o_frame)[3]);
  if (trace->link != -1) {
    printf("Snap link %i\n", trace->link);
    tnum = trace->link;
    goto again;
  }

  return 0;
}
