#include <cstdint> // for uint16_t
#include <cstdio>  // for printf, NULL
#include <cstdlib> // for exit
#include <vector>  // for vector
#include <assert.h>
// For runtime symbol
#include "bytecode.h" // for INS_B, INS_OP
#include "ir.h"       // for trace_s, ir_ins, snap_s, ir_ins_op, snap_entry_s
#include "opcodes.h"  // for JLOOP
#include "record.h"   // for trace_cache_get, record_side
#include "types.h"    // for symbol
#include "gc.h"

// Simple replay to test recording before we write a jit.
//#define USE_REG
#ifdef USE_REG
long res_load(std::vector<long> &res, int pc, std::vector<ir_ins> &ops) {
  assert(ops[pc].reg != REG_NONE);
  return res[ops[pc].reg];
}
void res_store(std::vector<long> &res, int pc, std::vector<ir_ins> &ops,
               long v) {
  assert(ops[pc].reg != REG_NONE);
  res[ops[pc].reg] = v;
}
#else
long res_load(std::vector<long> &res, int pc, std::vector<ir_ins> &ops) {
  return res[pc];
}
void res_store(std::vector<long> &res, int pc, std::vector<ir_ins> &ops,
               long v) {
  res[pc] = v;
}
#endif

long get_val_or_const(std::vector<long> &res, uint16_t v,
                      std::vector<ir_ins> &ops, std::vector<long> &consts) {
  if ((v & IR_CONST_BIAS) != 0) {
    return consts[v - IR_CONST_BIAS];
  }
  return res_load(res, v, ops);
}

snap_s *find_snap_for_pc(unsigned int pc, trace_s *trace) {
  snap_s *res = nullptr;
  for (auto &s : trace->snaps) {
    if (s.ir <= pc) {
      res = &s;
    }
  }
  return res;
}

extern uint8_t *alloc_ptr;
extern uint8_t *alloc_end;
extern long *frame_top;
extern long *stack;
extern unsigned int stacksz;
long *expand_stack_slowpath(long *frame);
void snap_restore(std::vector<long> &res, unsigned int **o_pc, long **o_frame,
                  snap_s *snap, trace_s *trace) {
  for (auto &slot : snap->slots) {
    if ((slot.val & IR_CONST_BIAS) != 0) {
      auto c = trace->consts[slot.val - IR_CONST_BIAS];
      if ((c & SNAP_FRAME) != 0u) {
        (*o_frame)[slot.slot] = c & ~SNAP_FRAME;
      } else {
        (*o_frame)[slot.slot] = c;
      }
    } else {
      //printf("Snap restore slot %i val %lx ptr %lx\n", slot.slot,  res[slot.val], &(*o_frame)[slot.slot]);
      (*o_frame)[slot.slot] = res_load(res, slot.val, trace->ops);
    }
  }
  if ((*o_frame + snap->offset) >= frame_top) {
    printf("Expand\n");
    auto pos = (*o_frame) - stack;
    expand_stack_slowpath(*o_frame);
    (*o_frame) = stack + pos;
  } 
  *o_frame = *o_frame + snap->offset;
  //printf("Tot remaining %li %li %li\n", frame_top - *o_frame, *o_frame + snap->offset, frame_top );
  *o_pc = snap->pc;
  // printf("PC is now %i %s\n", snap->pc, ins_names[INS_OP(**o_pc)]);
  // printf("Stack is now %li func is %lx\n", *o_frame-stack, func);
}

extern unsigned int *patchpc;
extern unsigned int patchold;
int record_run(unsigned int tnum, unsigned int **o_pc, long **o_frame,
               long *frame_top);

bool typecheck(long v, uint8_t ins_type) {
  auto type = ins_type & ~IR_INS_TYPE_GUARD;
  if (type == PTR_TAG) {
    assert(false);
  }
  if ((type&TAG_MASK) == LITERAL_TAG) {
    if ((v & IMMEDIATE_MASK) != type) {
      //printf("Type abort immediate: %lx vs %x\n", v&IMMEDIATE_MASK, type);
      return false;
    }
  } else {
    if ((v & TAG_MASK) != type) {
      //printf("Type abort %lx vs %x\n", v & TAG_MASK, type);
      return false;
    }
  }
  return true;
}

int record_run(unsigned int tnum, unsigned int **o_pc, long **o_frame,
               long *frame_top) {
  int loop_pc = -1;
again:
  auto *trace = trace_cache_get(tnum);

  unsigned int pc = 0;
  std::vector<long> res;
  res.resize(trace->ops.size());
looped:
  //printf("Run trace %i o_frame: %p\n", tnum, *o_frame);
  //printf("Frame %lx %lx %lx\n", (*o_frame)[0] , (*o_frame)[1] , (*o_frame)[2] );
  long *frame = *o_frame;

  while (pc < trace->ops.size()) {
    auto &ins = trace->ops[pc];
    // printf("Replay pc %i %s %i %i\n", pc, ir_names[(int)ins.op], ins.op1,
    //        ins.op2);
    // for (unsigned i = 0; i < pc; i++) {
    //   printf("%i: %lx ", i, res[i]);
    // }
    // printf("\n");
    switch (ins.op) {
    case ir_ins_op::ARG:
    case ir_ins_op::SLOAD: {
      auto v = frame[ins.op1];
      res_store(res, pc, trace->ops, v);
      if ((ins.type & IR_INS_TYPE_GUARD) != 0) {
	if (!typecheck(v, ins.type)) {
	  goto abort;
	}
      }
      pc++;
      break;
    }
    case ir_ins_op::LT: {
      auto a = get_val_or_const(res, ins.op1, trace->ops, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->ops, trace->consts);
      // printf("LT %li %li\n", a>>3, b>>3);
      if (a >= b) {
        goto abort;
      }
      pc++;
      break;
    }
    case ir_ins_op::GE: {
      auto a = get_val_or_const(res, ins.op1, trace->ops, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->ops, trace->consts);
      // printf("GE %li %li\n", a>>3, b>>3);
      if (a < b) {
        goto abort;
      }
      pc++;
      break;
    }
    case ir_ins_op::NE: {
      auto a = get_val_or_const(res, ins.op1, trace->ops, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->ops, trace->consts);
      // printf("EQ %li %li\n", a, b);
      if (a == b) {
        goto abort;
      }
      pc++;
      break;
    }
    case ir_ins_op::EQ: {
      auto a = get_val_or_const(res, ins.op1, trace->ops, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->ops, trace->consts);
      // printf("EQ %li %li\n", a, b);
      if (a != b) {
        goto abort;
      }
      pc++;
      break;
    }
    case ir_ins_op::GGET: {
      auto *a =
	(symbol *)(get_val_or_const(res, ins.op1, trace->ops, trace->consts) - SYMBOL_TAG);
      // printf("GGET %s %lx\n", a->name.c_str(), a->val);
      res_store(res, pc, trace->ops, a->val);
      if ((ins.type & IR_INS_TYPE_GUARD) != 0) {
	if (!typecheck(a->val, ins.type)) {
	  goto abort;
	}
      }
      pc++;
      break;
    }
    case ir_ins_op::SUB: {
      auto a = get_val_or_const(res, ins.op1, trace->ops, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->ops, trace->consts);
      // printf("SUB %li %li\n", a>>3, b>>3);
      long v;
      if (__builtin_sub_overflow(a, b, &v)) {
        goto abort;
      }
      res_store(res, pc, trace->ops, v);
      pc++;
      break;
    }
    case ir_ins_op::ADD: {
      auto a = get_val_or_const(res, ins.op1, trace->ops, trace->consts);
      auto b = get_val_or_const(res, ins.op2, trace->ops, trace->consts);
      // printf("ADD %li %li\n", a>>3, b>>3);
      long v;
      if (__builtin_add_overflow(a, b, &v)) {
        goto abort;
      }
      res_store(res, pc, trace->ops, v);
      pc++;
      break;
    }
    case ir_ins_op::CAR: {
      auto v = get_val_or_const(res, ins.op1, trace->ops, trace->consts);
      auto c = (cons_s*)(v - CONS_TAG);
      if (!typecheck(c->a, ins.type)) {
	goto abort;
      }
      res_store(res, pc, trace->ops, c->a);
      pc++;
      break;
    }
    case ir_ins_op::CDR: {
      auto v = get_val_or_const(res, ins.op1, trace->ops, trace->consts);
      auto c = (cons_s*)(v - CONS_TAG);
      if (!typecheck(c->b, ins.type)) {
	goto abort;
      }
      res_store(res, pc, trace->ops, c->b);
      pc++;
      break;
    }
    case ir_ins_op::ALLOC: {
      if ((alloc_ptr+ins.op1) >= alloc_end) {
	goto abort;
      }
      long* v = (long*)alloc_ptr;
      alloc_ptr += ins.op1;
      *v = ins.op2;
      res_store(res, pc, trace->ops, ((long)v) + ins.op2);
      pc++;
      break;
    }
    case ir_ins_op::REF: {
      char* ref = (char*)get_val_or_const(res, ins.op1, trace->ops, trace->consts);
      ref += ins.op2;
      res_store(res, pc, trace->ops, (long)ref);
      pc++;
      break;
    }
    case ir_ins_op::STORE: {
      long* ref = (long*)get_val_or_const(res, ins.op1, trace->ops, trace->consts);
      *ref = get_val_or_const(res, ins.op2, trace->ops, trace->consts);
      pc++;
      break;
    }
    // case ir_ins_op::CONS: {
    //   auto a = get_val_or_const(res, ins.op1, trace->ops, trace->consts);
    //   auto b = get_val_or_const(res, ins.op2, trace->ops, trace->consts);

    //   // TODO size check
    //   long c = (long)alloc_ptr;
    //   alloc_ptr += 24;
    //   auto cp = (cons_s*)(c);
    //   cp->type = CONS_TAG;
    //   cp->a = a;
    //   cp->b = b;
    //   res_store(res, pc, trace->ops, c + CONS_TAG);
    //   pc++;
    //   break;
    // }
    case ir_ins_op::RET: {
      long a = get_val_or_const(res, ins.op1, trace->ops, trace->consts) -
               SNAP_FRAME;
      auto b = get_val_or_const(res, ins.op2, trace->ops, trace->consts);
      if (a != frame[-1]) {
        //printf("RET guard %lx %lx\n", a, frame[-2]);
        goto abort;
      }
      frame -= (b >> 3);
      *o_frame -= (b >> 3);
      pc++;
      break;
    }
    case ir_ins_op::LOOP: {
      pc++;
      loop_pc = pc;
      break;
    }
    case ir_ins_op::PHI: {
      auto v = get_val_or_const(res, ins.op2, trace->ops, trace->consts);
      res_store(res, pc, trace->ops, v);
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
      //printf("Snap link finish: %i\n", trace->link);
      //  do NOT adjust frame jumping back to a root trace.
      if (loop_pc != -1) {
        pc = loop_pc;
        for (int i = trace->ops.size() - 1; i >= 0; i--) {
          auto &op = trace->ops[i];
          if (op.op != ir_ins_op::PHI) {
            break;
          }
          res[op.op1] = res[i];
        }
	//printf("Loop trace %i\n", trace->link);
        goto looped;
      }
      tnum = trace->link;
      goto again;
    }
    printf("Fell off end of trace %i\n", tnum);

    return 0;
  }
abort : {
  auto *snap = find_snap_for_pc(pc, trace);
  snap_restore(res, o_pc, o_frame, snap, trace);

  if (snap->link != -1) {
    // Don't adjust stack frame for links
    // TODO: infact, in generated code snap_restore will be not done at all when
    // jumping to side trace.
    //printf("Snaplink to %i\n", snap->link);
    *o_frame = *o_frame - snap->offset;
    tnum = snap->link;
    goto again;
  }

  // printf("Replay failed guard in trace %i, abort ir pc %i, hotness %i\n",
  //        trace->num, pc, snap->exits);
  if (snap->exits < 10) {
    snap->exits++;
  } else {
    if (snap->exits < 14) {
      snap->exits++;
      printf("Hot snap %i from trace %i\n", pc, trace->num);
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
  if (INS_OP(**o_pc) == JLOOP) {
      auto *otrace = trace_cache_get(INS_B(**o_pc));
      if (INS_OP(otrace->startpc) == LOOP) {
        (*o_pc)++;
      } else {
        *o_pc = &otrace->startpc;
      }
    printf("Exit to loop\n");
    return 0;
  }
  // printf("Exit trace %i\n", tnum);

  return 0;
}

  return 0;
}
