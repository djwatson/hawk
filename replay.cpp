#include "record.h"
// TODO for runtime symbol
#include "bytecode.h"

#include <stdio.h>
#include <stdlib.h>

// Simple replay to test recording before we write a jit.

long get_val_or_const(std::vector<long> &res, uint16_t v,
                      std::vector<long> &consts) {
  if (v & IR_CONST_BIAS) {
    return consts[v - IR_CONST_BIAS];
  }
  return res[v];
}

snap_s *find_snap_for_pc(unsigned int pc, trace_s *trace) {
  snap_s *res = NULL;
  for (auto &s : trace->snaps) {
    if (s.ir <= pc) {
      res = &s;
    }
  }
  return res;
}

extern long *stack;
extern unsigned int stacksz;
extern __attribute__((noinline)) void EXPAND_STACK_SLOWPATH();
void snap_restore(std::vector<long> &res, unsigned int **o_pc, long **o_frame,
                  snap_s *snap, trace_s *trace) {
  for (auto &slot : snap->slots) {
    if (slot.val & IR_CONST_BIAS) {
      auto c = trace->consts[slot.val - IR_CONST_BIAS];
      if (c & SNAP_FRAME) {
        (*o_frame)[slot.slot] = c & ~SNAP_FRAME;
      } else {
        (*o_frame)[slot.slot] = c;
      }
    } else {
      if ((*o_frame) + slot.slot >= stack + stacksz) {
	auto pos = (*o_frame) - stack;
	EXPAND_STACK_SLOWPATH();
	(*o_frame) = stack + pos;
	// TODO update frame_top
      }
      // printf("Snap restore slot %i val %li ptr %lx\n", slot.slot,
      // res[slot.val], &(*o_frame)[slot.slot]);
      (*o_frame)[slot.slot] = res[slot.val];
    }
  }
  *o_frame = *o_frame + snap->offset;
  bcfunc *func = (bcfunc *)((*o_frame)[-1] - 5);
  *o_pc = &func->code[snap->pc];
  // printf("PC is now %i %s\n", snap->pc, ins_names[INS_OP(**o_pc)]);
  // printf("Stack is now %li func is %lx\n", *o_frame-stack, func);
}

extern unsigned int *patchpc;
extern unsigned int patchold;
int record_run(unsigned int tnum, unsigned int **o_pc, long **o_frame,
               long *frame_top);
int replay_abort(unsigned int ir_pc, trace_s *trace, std::vector<long> &res,
                 unsigned int **o_pc, long **o_frame) {}

int record_run(unsigned int tnum, unsigned int **o_pc, long **o_frame,
               long *frame_top) {
again:
  auto trace = trace_cache_get(tnum);
  // printf("Run trace %i\n", tnum);
  // printf("Frame %li %li\n", (*o_frame)[0] >> 3, (*o_frame)[1] >> 3);

  unsigned int pc = 0;
  std::vector<long> res;
  res.resize(trace->ops.size());

  long *frame = *o_frame;

  while (pc < trace->ops.size()) {
    auto &ins = trace->ops[pc];
    // printf("Replay pc %i %s %i %i\n", pc, ir_names[(int)ins.op], ins.op1,
    // ins.op2); for(int i = 0; i < pc; i++) {
    //   printf("%i: %lx ", i, res[i]);
    // }
    // printf("\n");
    switch (ins.op) {
    case ir_ins_op::SLOAD: {
      res[pc] = frame[ins.op1];
      if (ins.type&IR_INS_TYPE_GUARD) {
	if ((res[pc] & 0x7) != (ins.type&~IR_INS_TYPE_GUARD)) {
	  printf("Type abort\n");
	  goto abort;
	}
      }
      pc++;
      break;
    }
    case ir_ins_op::LT: {
      auto a = get_val_or_const(res, ins.op1, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      // printf("LT %li %li\n", a>>3, b>>3);
      if (a >= b) {
        goto abort;
      }
      pc++;
      break;
    }
    case ir_ins_op::GE: {
      auto a = get_val_or_const(res, ins.op1, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      // printf("GE %li %li\n", a>>3, b>>3);
      if (a < b) {
        goto abort;
      }
      pc++;
      break;
    }
    case ir_ins_op::NE: {
      auto a = get_val_or_const(res, ins.op1, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      // printf("EQ %li %li\n", a, b);
      if (a == b) {
        goto abort;
      }
      pc++;
      break;
    }
    case ir_ins_op::EQ: {
      auto a = get_val_or_const(res, ins.op1, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      // printf("EQ %li %li\n", a, b);
      if (a != b) {
        goto abort;
      }
      pc++;
      break;
    }
    case ir_ins_op::GGET: {
      symbol *a = (symbol *)get_val_or_const(res, ins.op1, trace->consts);
      // printf("GGET %s %lx\n", a->name.c_str(), a->val);
      res[pc] = a->val;
      if (ins.type&IR_INS_TYPE_GUARD) {
	if ((res[pc] & 0x7) != (ins.type&~IR_INS_TYPE_GUARD)) {
	  printf("Type abort\n");
	  goto abort;
	}
      }
      pc++;
      break;
    }
    case ir_ins_op::SUB: {
      auto a = get_val_or_const(res, ins.op1, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      // printf("SUB %li %li\n", a>>3, b>>3);
      if (__builtin_sub_overflow(a, b, &res[pc])) {
        goto abort;
      }
      pc++;
      break;
    }
    case ir_ins_op::ADD: {
      auto a = get_val_or_const(res, ins.op1, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      // printf("ADD %li %li\n", a>>3, b>>3);
      if (__builtin_add_overflow(a, b, &res[pc])) {
        goto abort;
      }
      pc++;
      break;
    }
    case ir_ins_op::RET: {
      auto a = get_val_or_const(res, ins.op1, trace->consts) - SNAP_FRAME;
      auto b = get_val_or_const(res, ins.op2, trace->consts);
      if (a != frame[-2]) {
        // printf("RET guard %lx %lx\n", a, frame[-2]);
        goto abort;
      }
      frame -= (b >> 3);
      *o_frame -= (b >> 3);
      pc++;
      break;
    }
    default: {
      printf("Unknown replay op: %s\n", ir_names[(int)ins.op]);
      exit(-1);
    }
    }
  }
  // printf("At end of trace\n");
  {
    auto &snap = trace->snaps[trace->snaps.size() - 1];
    snap_restore(res, o_pc, o_frame, &snap, trace);
    if (trace->link != -1) {
      // printf("Snap link %i\n", trace->link);
      //  do NOT adjust frame jumping back to a root trace.
      tnum = trace->link;
      goto again;
    }
    printf("Fell off end of trace %i\n", tnum);

    return 0;
  }
abort : {
  auto snap = find_snap_for_pc(pc, trace);
  snap_restore(res, o_pc, o_frame, snap, trace);

  if (snap->link != -1) {
    // Don't adjust stack frame for links
    // TODO: infact, in generated code snap_restore will be not done at all when
    // jumping to side trace.
    // printf("Snaplink to %i\n", snap->link);
    *o_frame = *o_frame - snap->offset;
    tnum = snap->link;
    goto again;
  }

  // printf("Replay failed guard in trace %i, abort ir pc %i, hotness %i\n",
  // trace->num, pc, snap->exits);
  if (snap->exits < 10) {
    snap->exits++;
  } else {
    if (snap->exits < 14) {
      snap->exits++;
      printf("Hot snap %i\n", pc);
      if (INS_OP(**o_pc) == JLOOP) {
        printf("HOT SNAP to JLOOP\n");
        patchpc = *o_pc;
        patchold = **o_pc;
        **o_pc = trace->startpc;
      }
      record_side(trace, snap);
      return 1;
    }
    if (snap->exits == 14) {
      printf("Side max\n");
      snap->exits++;
    }
  }
  if (INS_OP(**o_pc) == JLOOP) {
    *o_pc = &trace->startpc;
    printf("Exit to loop\n");
    return 0;
  }
  // printf("Exit trace %i\n", tnum);

  return 0;
}

  return 0;
}
