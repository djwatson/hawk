#include "record.h"
#include "asm_x64.h"  // for REG_NONE, asm_jit, reg_names
#include "bytecode.h" // for INS_A, INS_B, INS_OP, INS_C, INS_D, bcfunc
#include "ir.h"       // for ir_ins, trace_s, ir_ins_op, ir_ins::(anonymous...
#include "opcodes.h"
#include "snap.h"  // for add_snap, snap_replay
#include "types.h" // for CONS_TAG, FALSE_REP, SYMBOL_TAG, symbol, CLOSU...
#include "vm.h"    // for find_func_for_frame, hotmap_mask, hotmap_sz
#include <cassert> // for assert
#include <cstdint> // for uint32_t
#include <cstdio>  // for printf
#include <cstdlib> // for exit
#include <cstring> // for NULL, memmove, size_t
#include <memory>  // for allocator_traits<>::value_type
#include <string>  // for string
#include <vector>  // for vector

void opt_loop(trace_s *trace, int *regs);

unsigned int *pc_start;
unsigned int instr_count;
int depth = 0;

long func;
int regs_list[257];
int *regs = &regs_list[1];
snap_s *side_exit = nullptr;
trace_s *parent = nullptr;

std::vector<unsigned int *> downrec;

enum trace_state_e {
  OFF = 0,
  START,
  TRACING,
};

trace_state_e trace_state = OFF;
trace_s *trace = nullptr;
std::vector<trace_s *> traces;

unsigned int *patchpc = nullptr;
unsigned int patchold;

void pendpatch() {
  if (patchpc != nullptr) {
    printf("PENDPACTCH\n");
    *patchpc = patchold;
    patchpc = nullptr;
  }
}

void print_const_or_val(int i, trace_s *ctrace) {
  if ((i & IR_CONST_BIAS) != 0) {
    auto c = ctrace->consts[i - IR_CONST_BIAS];
    int type = c & 0x7;
    if ((c & SNAP_FRAME) != 0u) {
      printf("(pc %li)", c & ~SNAP_FRAME);
    } else if (type == 0) {
      printf("\e[1;35m%li\e[m", c >> 3);
    } else if (type == 5) {
      printf("\e[1;31m<closure>\e[m");
    } else if (c == FALSE_REP) {
      printf("\e[1;35m#f\e[m");
    } else if (c == TRUE_REP) {
      printf("\e[1;35m#t\e[m");
    } else if (c == NIL_TAG) {
      printf("\e[1;35mnil\e[m");
    } else if (type == 3) {
      printf("\e[1;35mcons\e[m");
    } else {
      printf("Unknown dump_trace type %i\n", type);
      exit(-1);
    }
  } else {
    printf("%04d", i);
  }
}

void dump_trace(trace_s *ctrace) {
  unsigned long cur_snap = 0;
  for (size_t i = 0; i < ctrace->ops.size() + 1 /* extra snap */; i++) {
    // Print any snap
    while ((cur_snap < ctrace->snaps.size()) &&
           ctrace->snaps[cur_snap].ir == i) {

      auto &snap = ctrace->snaps[cur_snap];
      printf("SNAP[ir=%i pc=%lx off=%i", snap.ir, (long)snap.pc, snap.offset);
      for (auto &entry : snap.slots) {
        printf(" %i=", entry.slot);
        print_const_or_val(entry.val, ctrace);
      }
      printf("]\n");
      cur_snap++;
    }
    if (i == ctrace->ops.size()) {
      break;
    }

    auto op = ctrace->ops[i];
    printf("%04zu %s %c\t", i, reg_names[op.reg],
           (op.type & IR_INS_TYPE_GUARD) != 0 ? '>' : ' ');
    auto t = op.type & TAG_MASK;
    if (t == 0) {
      printf("\e[1;35mfix \e[m ");
    } else if (t == 5) {
      printf("\e[1;31mclo \e[m ");
    } else if (t == 3) {
      printf("\e[1;34mcons\e[m ");
    } else if (t == 2) {
      printf("\e[1;34mflo \e[m ");
    } else if (t == 6) {
      printf("\e[1;34msym \e[m ");
    } else if (t == 7) {
      printf("\e[1;34mlit \e[m ");
    } else {
      printf("\e[1;34mUNK \e[m ");
    }
    printf("%s ", ir_names[(int)op.op]);
    switch (op.op) {
    case ir_ins_op::CAR:
    case ir_ins_op::CDR:
    case ir_ins_op::KFIX:
    case ir_ins_op::ARG:
    case ir_ins_op::SLOAD: {
      print_const_or_val(op.op1, ctrace);
      break;
    }
    case ir_ins_op::GGET: {
      auto *s = (symbol *)(ctrace->consts[op.op1 - IR_CONST_BIAS] - SYMBOL_TAG);
      printf("%s", s->name->str);
      break;
    }
    case ir_ins_op::ALLOC: {
      printf("%i type %i", op.op1, op.op2);
      break;
    }
    case ir_ins_op::RET:
    case ir_ins_op::PHI:
    case ir_ins_op::SUB:
    case ir_ins_op::ADD:
    case ir_ins_op::EQ:
    case ir_ins_op::NE:
    case ir_ins_op::GE:
    case ir_ins_op::LT:
    case ir_ins_op::STORE:
    case ir_ins_op::CLT: {
      print_const_or_val(op.op1, ctrace);
      printf(" ");
      print_const_or_val(op.op2, ctrace);
      break;
    }
    case ir_ins_op::REF: {
      print_const_or_val(op.op1, ctrace);
      printf(" offset %i", op.op2);
      break;
    }
    case ir_ins_op::LOOP: {
      printf("----------------");
      break;
    }
    default:
      printf("Can't dump_trace ir type: %s\n", ir_names[(int)op.op]);
      exit(-1);
    }
    printf("\n");
  }
}

void record_side(trace_s *p, snap_s *side) {
  parent = p;
  side_exit = side;
}

void record_abort();
void record_start(unsigned int *pc, long *frame) {
  trace = new trace_s;
  trace->num = traces.size();
  trace_state = START;
  func = (long)find_func_for_frame(pc);
  assert(func);
  printf("Record start %i at %s func %s\n", trace->num, ins_names[INS_OP(*pc)],
         ((bcfunc *)func)->name.c_str());
  if (parent != nullptr) {
    printf("Parent %i\n", parent->num);
  }
  pc_start = pc;
  trace->startpc = *pc;
  instr_count = 0;
  depth = 0;
  regs = &regs_list[1];
  for (int &i : regs_list) {
    i = -1;
  }

  if (side_exit != nullptr) {
    snap_replay(&regs, side_exit, parent, trace, frame, &depth);
  }
  add_snap(regs_list, regs - regs_list - 1, trace,
           INS_OP(*pc) == FUNC ? pc + 1 : pc);
}

extern int joff;
extern unsigned TRACE_MAX;

void record_stop(unsigned int *pc, long *frame, int link) {
  auto offset = regs - regs_list - 1;
  add_snap(regs_list, offset, trace, pc);
  if (link == (int)traces.size() && offset == 0) {
    // Attempt to loop-fiy it.
    // opt_loop(trace, regs);
  }

  // if (trace->ops.size() <= 3) {
  //   printf("Record abort: trace too small\n");
  //   record_abort();
  //   return;
  // }

  pendpatch();

  if (side_exit != nullptr) {
    side_exit->link = traces.size();
  } else {
    auto op = INS_OP(*pc_start);
    if (op != RET1 && op != LOOP) {
      *pc_start = CODE(JFUNC, INS_A(*pc_start), traces.size(), 0);
    } else {
      *pc_start = CODE(JLOOP, 0, traces.size(), 0);
    }
  }
  printf("Installing trace %li\n", traces.size());

  trace->link = link;
  traces.push_back(trace);

#ifndef REPLAY
  asm_jit(trace, side_exit, parent);
#endif
  dump_trace(trace);

  trace_state = OFF;
  side_exit = nullptr;
  downrec.clear();
  trace = nullptr;
  // joff = 1;
}

void record_abort() {
  pendpatch();
  delete trace;
  trace = nullptr;
  trace_state = OFF;
  side_exit = nullptr;
  downrec.clear();
}

int record(unsigned int *pc, long *frame, long argcnt) {
  if (traces.size() >= TRACE_MAX) {
    return 1;
  }
  switch (trace_state) {
  case OFF: {
    // TODO fix?
    if (INS_OP(*pc) == JFUNC && side_exit == nullptr) {
      // printf("CAN'T RECORD TO JFUNC\n");
      return 1;
    }
    record_start(pc, frame);
    auto res = record_instr(pc, frame, argcnt);
    if (trace_state == START) {
      trace_state = TRACING;
    }
    return res;
    break;
  }
  case TRACING: {
    pendpatch();
    auto res = record_instr(pc, frame, argcnt);
    return res;
    break;
  }
  default: {
    printf("BAD TRACE STATE %i\n", trace_state);
    exit(-1);
    return 1;
  }
  }
}

int record_stack_load(int slot, const long *frame) {
  if (regs[slot] == -1) {
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op1 = slot;
    ins.op = ir_ins_op::SLOAD;
    // Guard on type
    auto type = frame[slot] & 0x7;
    if (type == LITERAL_TAG) {
      type = frame[slot] & IMMEDIATE_MASK;
    }
    if (type == PTR_TAG) {
      //assert(false);
    }
    ins.type = IR_INS_TYPE_GUARD | type;

    regs[slot] = trace->ops.size();
    trace->ops.push_back(ins);
  }
  return regs[slot];
}

extern unsigned char hotmap[hotmap_sz];
int record_instr(unsigned int *pc, long *frame, long argcnt) {
  unsigned int i = *pc;

  if (INS_OP(i) == LOOP) {
    for (int *pos = &regs[INS_A(i)]; pos < &regs_list[257]; pos++) {
      *pos = -1;
    }
  } else if (INS_OP(i) == CLFUNC) {
    // If it doesn't match, just continue;
    if (argcnt != INS_A(i)) {
      return 0;
    }
  }
  if ((pc == pc_start) && (depth == 0) && (trace_state == TRACING) &&
      INS_OP(trace->startpc) != RET1 && parent == nullptr) {
    printf("Record stop loop\n");
    record_stop(pc, frame, traces.size());
    return 1;
  }

  instr_count++;
  for (int j = 0; j < depth; j++) {
    printf(" . ");
  }
  printf("%lx %s %i %i %i\n", (long)pc, ins_names[INS_OP(i)], INS_A(i),
         INS_B(i), INS_C(i));
  switch (INS_OP(i)) {
  case LOOP:
  case CLFUNC: {
    break;
  }
  case FUNC: {
    // if (trace->ops.size() == 0) {
    //   for(unsigned arg = 0; arg < INS_A(*pc); arg++) {
    // 	ir_ins ins;
    // 	ins.reg = REG_NONE;
    // 	ins.op1 = arg;
    // 	ins.op = ir_ins_op::ARG;
    // 	// Guard on type
    // 	auto type = frame[arg] & 0x7;
    // 	ins.type = type;

    // 	regs[arg] = trace->ops.size();
    // 	trace->ops.push_back(ins);

    //   }
    //}
    // TODO: argcheck?
    break;
  }
  case RET1: {
    if (depth == 0) {
      auto *old_pc = (unsigned int *)frame[-1];
      if (INS_OP(*pc_start) == RET1 || side_exit != nullptr) {
        int cnt = 0;
        for (auto &p : downrec) {
          if (p == pc) {
            cnt++;
          }
        }
        if (cnt != 0) {
          if (side_exit != nullptr) {
            printf("Record abort: Potential down-recursion, restarting\n");
            record_abort();
            record_start(pc, frame);
            record_instr(pc, frame, 0);
            trace_state = TRACING;
            break;
          }
          printf("Record stop downrec\n");
          record_stop(pc, frame, traces.size());
          return 1;
        }
        downrec.push_back(pc);

        auto result = record_stack_load(INS_A(i), frame);
        // Guard down func type
        add_snap(regs_list, regs - regs_list - 1, trace, pc);

        auto frame_off = INS_A(*(old_pc - 1));
        printf("Continue down recursion, frame offset %i\n", frame_off);

        memmove(&regs[frame_off + 1], &regs[0],
                sizeof(int) * (256 - (frame_off + 1)));
        regs[frame_off] = result;
        for (unsigned j = 0; j < frame_off; j++) {
          regs[j] = -1;
        }

        auto knum = trace->consts.size();
        trace->consts.push_back((long)old_pc | SNAP_FRAME);
        auto knum2 = trace->consts.size();
        trace->consts.push_back((frame_off + 1) << 3);
        ir_ins ins;
        ins.reg = REG_NONE;
        ins.op1 = knum | IR_CONST_BIAS;
        // TODO this isn't a runtime const?  can gen directly from PC?
        ins.op2 = knum2 | IR_CONST_BIAS;
        ins.op = ir_ins_op::RET;
        ins.type = IR_INS_TYPE_GUARD | 0x5;
        trace->ops.push_back(ins);

        add_snap(regs_list, regs - regs_list - 1, trace, (uint32_t*)frame[-1]);
        // TODO retdepth
      } else {
	if (INS_OP(trace->startpc) == LOOP && parent == nullptr) {
	  printf("Record abort: Loop root trace exited loop\n");
	  record_abort();
	} else {
	  printf("Record stop return\n");
	  record_stop(pc, frame, -1);
	}
        return 1;
      }
    } else if (depth > 0) {
      depth--;
      regs[-1] = regs[INS_A(i)];
      for (int j = regs - regs_list; j < 257; j++) {
        regs_list[j] = -1;
      }
      auto *old_pc = (unsigned int *)frame[-1];
      regs -= (INS_A(*(old_pc - 1)) + 1);
    } else {
      depth--;
      printf("TODO return below trace\n");
      exit(-1);
    }
    break;
  }
  case CALL: {
    // TODO this needs to check reg[]links instead
    for (unsigned j = INS_A(i) + 1; j < INS_A(i) + INS_B(i); j++) {
      regs[j] = record_stack_load(j, frame);
    }

    // Check call type
    {
      auto v = frame[INS_A(i) + 1];
      auto knum = trace->consts.size();
      trace->consts.push_back(v);
      ir_ins ins;
      ins.reg = REG_NONE;
      ins.op1 = record_stack_load(INS_A(i) + 1, frame);
      ins.op2 = knum | IR_CONST_BIAS;
      ins.op = ir_ins_op::EQ;
      // TODO magic number
      ins.type = IR_INS_TYPE_GUARD | 0x5;
      trace->ops.push_back(ins);
    }
    long cnt = 0;
    auto *p_pc = (uint32_t *)frame[-1];
    for (int d = depth; d > 0; d--) {
      if (p_pc == pc + 1) {
        cnt++;
      }
      p_pc = (uint32_t *)frame[-1];
    }

    // Setup frame
    depth++;
    // Push PC link as const
    {
      auto knum = trace->consts.size();
      trace->consts.push_back(((long)(pc + 1)) | SNAP_FRAME);
      regs[INS_A(i)] = knum | IR_CONST_BIAS; // TODO set PC
    }

    // Increment regs
    regs += INS_A(i) + 1;

    if (cnt >= UNROLL_LIMIT) {
      auto v = frame[INS_A(i) + 1];
      auto *closure = (closure_s *)(v - CLOSURE_TAG);
      auto *cfunc = (bcfunc *)closure->v[0];
      auto *target = (cfunc->code).data();
      if (target == pc_start) {
        printf("Record stop up-recursion\n");
        record_stop(target, frame, traces.size());
        return 1;
      } // TODO fix flush
      pendpatch();
      if (INS_OP(cfunc->code[0]) == JFUNC) {
        printf("Flushing trace\n");
        cfunc->code[0] = traces[INS_D(cfunc->code[0])]->startpc;
        hotmap[(((long)pc) >> 2) & hotmap_mask] = 1;
      }
      // TODO this isn't in luajit? fails with side exit without?
      hotmap[(((long)pc) >> 2) & hotmap_mask] = 1;
      printf("Record abort: unroll limit reached\n");
      record_abort();
      return 1;
    }
    break;
  }
  case KSHORT: {
    auto k = INS_D(i) << 3;
    auto reg = INS_A(i);
    regs[reg] = trace->consts.size() | IR_CONST_BIAS;
    trace->consts.push_back(k);
    break;
  }
  case ISLT: {
    add_snap(regs_list, regs - regs_list - 1, trace, pc);
    auto reg = INS_A(i);
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op1 = record_stack_load(INS_B(i), frame);
    ins.op2 = record_stack_load(INS_C(i), frame);
    ins.op = ir_ins_op::CLT;
    ins.type = 0; // TODO bool
    regs[reg] = trace->ops.size();
    trace->ops.push_back(ins);
    break;
  }
  case JISF: {
    // TODO snaps
    add_snap(regs_list, regs - regs_list - 1, trace, pc);
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op1 = record_stack_load(INS_B(i), frame);
    auto knum = trace->consts.size();
    trace->consts.push_back(FALSE_REP);
    ins.op2 = knum | IR_CONST_BIAS;
    if (frame[INS_B(i)] == FALSE_REP) {
      ins.op = ir_ins_op::EQ;
    } else {
      ins.op = ir_ins_op::NE;
    }
    ins.type = IR_INS_TYPE_GUARD;
    trace->ops.push_back(ins);
    break;
  }
  case JISLT: {
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op1 = record_stack_load(INS_B(i), frame);
    ins.op2 = record_stack_load(INS_C(i), frame);
    uint32_t* next_pc;
    if (frame[INS_B(i)] < frame[INS_C(i)]) {
      ins.op = ir_ins_op::LT;
      add_snap(regs_list, regs - regs_list - 1, trace, pc + INS_D(*(pc + 1)) + 1);
      next_pc = pc + 2;
    } else {
      ins.op = ir_ins_op::GE;
      add_snap(regs_list, regs - regs_list - 1, trace, pc + 2);
      next_pc = pc + INS_D(*(pc + 1)) + 1;
    }
    ins.type = IR_INS_TYPE_GUARD;
    trace->ops.push_back(ins);
    add_snap(regs_list, regs - regs_list - 1, trace, next_pc);
    break;
  }
  case JISEQ: {
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op1 = record_stack_load(INS_B(i), frame);
    ins.op2 = record_stack_load(INS_C(i), frame);
    uint32_t* next_pc;
    if (frame[INS_B(i)] == frame[INS_C(i)]) {
      ins.op = ir_ins_op::EQ;
      add_snap(regs_list, regs - regs_list - 1, trace, pc + INS_D(*(pc + 1)) + 1);
      next_pc = pc + 2;
    } else {
      ins.op = ir_ins_op::NE;
      add_snap(regs_list, regs - regs_list - 1, trace, pc + 2);
      next_pc = pc + INS_D(*(pc + 1)) + 1;
    }
    ins.type = IR_INS_TYPE_GUARD;
    trace->ops.push_back(ins);
    add_snap(regs_list, regs - regs_list - 1, trace, next_pc);
    break;
  }
  case CDR:
  case CAR: {
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op1 = record_stack_load(INS_B(i), frame);
    if (INS_OP(i) == CAR) {
      // TODO typecheck
      // TODO cleanup
      ins.type = ((cons_s*)(frame[INS_B(i)] - CONS_TAG))->a & TAG_MASK;
      if (ins.type == LITERAL_TAG) {
	ins.type = ((cons_s*)(frame[INS_B(i)] - CONS_TAG))->a & IMMEDIATE_MASK;
      }
      ins.op = ir_ins_op::CAR;
    } else {
      ins.type = ((cons_s*)(frame[INS_B(i)] - CONS_TAG))->b & TAG_MASK;
      if (ins.type == LITERAL_TAG) {
	ins.type = ((cons_s*)(frame[INS_B(i)] - CONS_TAG))->b & IMMEDIATE_MASK;
      }
      ins.op = ir_ins_op::CDR;
    }
    ins.type |= IR_INS_TYPE_GUARD;
    regs[INS_A(i)] = trace->ops.size();
    trace->ops.push_back(ins);
    break;
  }
  case JGUARD: {
    record_stack_load(INS_B(i), frame);
    long tag = INS_C(i);

    if (tag == PTR_TAG) {
      // TODO should be checked by sload??
      assert(false);
    } else if (tag < LITERAL_TAG) {
      // Nothing to do, SLOAD already checked.
    } else {
      // Nothing to do, SLOAD already checked.
    }
    break;
  }
  case KONST: {
    auto k = const_table[INS_D(i)];
    auto reg =  INS_A(i);
    auto knum = trace->consts.size();
    trace->consts.push_back(k);
    regs[reg] = IR_CONST_BIAS + knum;
    break;
  }
  case CONS: {
    add_snap(regs_list, regs - regs_list - 1, trace, pc);
    trace->snaps[trace->snaps.size() - 1].exits = 100;
    auto a = record_stack_load(INS_B(i), frame);
    auto b = record_stack_load(INS_C(i), frame);
    {
      ir_ins ins;
      ins.type = CONS_TAG;
      ins.reg = REG_NONE;
      ins.op1 = sizeof(cons_s);
      ins.op2 = CONS_TAG;
      ins.op = ir_ins_op::ALLOC;
      regs[INS_A(i)] = trace->ops.size();
      trace->ops.push_back(ins);
    }
    auto cell = trace->ops.size() - 1;
    {
      ir_ins ins;
      ins.type = 0;
      ins.reg = REG_NONE;
      ins.op1 = cell;
      ins.op2 = 8 - CONS_TAG;
      ins.op = ir_ins_op::REF;
      trace->ops.push_back(ins);
    }
    {
      ir_ins ins;
      ins.type = 0;
      ins.reg = REG_NONE;
      ins.op1 = trace->ops.size() - 1;
      ins.op2 = a;
      ins.op = ir_ins_op::STORE;
      trace->ops.push_back(ins);
    }
    {
      ir_ins ins;
      ins.type = 0;
      ins.reg = REG_NONE;
      ins.op1 = cell;
      ins.op2 = 8 + 8 - CONS_TAG;
      ins.op = ir_ins_op::REF;
      trace->ops.push_back(ins);
    }
    {
      ir_ins ins;
      ins.type = 0;
      ins.reg = REG_NONE;
      ins.op1 = trace->ops.size() - 1;
      ins.op2 = b;
      ins.op = ir_ins_op::STORE;
      trace->ops.push_back(ins);
    }
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1);

    break;
  }
  case MOV: {
    regs[INS_A(i)] = record_stack_load(INS_B(i), frame);
    // TODO loop moves can clear
    // regs[INS_B(i)] = -1;
    break;
  }
  case GGET: {
    // TODO GSET
    long gp = const_table[INS_D(i)];
    auto reg = INS_A(i);
    bool done = false;
    for (int j = trace->ops.size() - 1; j >= 0; j--) {
      auto &op = trace->ops[j];
      if (op.op == ir_ins_op::GGET &&
          trace->consts[op.op1 - IR_CONST_BIAS] == gp) {
        done = true;
        regs[reg] = j;
        break;
      }
    }
    if (!done) {
      auto knum = trace->consts.size();
      trace->consts.push_back(gp);
      ir_ins ins;
      ins.reg = REG_NONE;
      ins.op1 = knum | IR_CONST_BIAS;
      ins.op = ir_ins_op::GGET;
      ins.type = IR_INS_TYPE_GUARD | (((symbol *)(gp - SYMBOL_TAG))->val & 0x7);
      regs[reg] = trace->ops.size();
      trace->ops.push_back(ins);
    }
    break;
  }
  case SUBVN: {
    ir_ins ins;
    ins.reg = REG_NONE;
    auto knum = trace->consts.size();
    trace->consts.push_back(INS_C(i) << 3);
    ins.op1 = record_stack_load(INS_B(i), frame);
    ins.op2 = knum | IR_CONST_BIAS;
    ins.op = ir_ins_op::SUB;
    ins.type = IR_INS_TYPE_GUARD;
    auto reg = INS_A(i);
    regs[reg] = trace->ops.size();
    trace->ops.push_back(ins);
    break;
  }
  case ADDVN: {
    ir_ins ins;
    ins.reg = REG_NONE;
    auto knum = trace->consts.size();
    trace->consts.push_back(INS_C(i) << 3);
    ins.op1 = record_stack_load(INS_B(i), frame);
    ins.op2 = knum | IR_CONST_BIAS;
    ins.op = ir_ins_op::ADD;
    ins.type = IR_INS_TYPE_GUARD;
    auto reg = INS_A(i);
    regs[reg] = trace->ops.size();
    trace->ops.push_back(ins);
    break;
  }
  case ADDVV: {
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op1 = record_stack_load(INS_B(i), frame);
    ins.op2 = record_stack_load(INS_C(i), frame);
    ins.op = ir_ins_op::ADD;
    // TODO: Assume no type change??
    uint8_t type = 0;
    if (ins.op1 >= IR_CONST_BIAS) {
      type = trace->consts[ins.op1 - IR_CONST_BIAS] & TAG_MASK;
    } else {
      type = trace->ops[ins.op1].type;
    }
    ins.type = IR_INS_TYPE_GUARD | type;
    auto reg = INS_A(i);
    regs[reg] = trace->ops.size();
    trace->ops.push_back(ins);
    break;
  }
  case SUBVV: {
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op1 = record_stack_load(INS_B(i), frame);
    ins.op2 = record_stack_load(INS_C(i), frame);
    ins.op = ir_ins_op::SUB;
    // TODO: Assume no type change??
    uint8_t type = 0;
    if (ins.op1 >= IR_CONST_BIAS) {
      type = trace->consts[ins.op1 - IR_CONST_BIAS] & TAG_MASK;
    } else {
      type = trace->ops[ins.op1].type;
    }
    ins.type = IR_INS_TYPE_GUARD | type;
    auto reg = INS_A(i);
    regs[reg] = trace->ops.size();
    trace->ops.push_back(ins);
    break;
  }
  case CALLT: {
    // Check call type
    {
      auto v = frame[INS_A(i) + 1];
      auto knum = trace->consts.size();
      trace->consts.push_back(v);
      ir_ins ins;
      ins.reg = REG_NONE;
      ins.op1 = record_stack_load(INS_A(i) + 1, frame);
      ins.op2 = knum | IR_CONST_BIAS;
      ins.op = ir_ins_op::EQ;
      // TODO magic number
      ins.type = IR_INS_TYPE_GUARD | 0x5;
      trace->ops.push_back(ins);
    }
    // Move args down
    // TODO also chedck func
    for (unsigned j = INS_A(i) + 1; j < INS_A(i) + INS_B(i); j++) {
      regs[j] = record_stack_load(j, frame);
    }
    memmove(&regs[0], &regs[INS_A(i) + 1], sizeof(int) * (INS_B(i) - 1));
    for (int j = INS_B(i) - 1; j < 256; j++) {
      if (&regs[j] >= regs_list + 256) {
        break;
      }
      regs[j] = -1;
    }

    break;
  }
  case JMP: {
    break;
  }
  case JFUNC: {
    // Check if it is a returning trace
    auto *ctrace = trace_cache_get(INS_B(i));
    if (ctrace->link == -1) {
      assert(patchpc == nullptr);
      patchpc = pc;
      patchold = *pc;
      *pc = traces[INS_D(*pc)]->startpc;
      break;
    }
    for (unsigned j = 0; j < INS_A(i); j++) {
      regs[j] = record_stack_load(j, frame);
    }
    printf("Record stop JFUNC\n");
    record_stop(pc, frame, INS_B(i));
    return 1;
  }
  case JLOOP: {
    if (side_exit == nullptr) {
      printf("Record abort: root trace hit loop\n");
      record_abort();
      return 1;
    }
    printf("Record stop hit JLOOP\n");
    // NOTE: stack load is for ret1 jloop returns.  Necessary?
    // TODO JLOOp also used for loop, only need to record for RET
    regs[INS_A(i)] = record_stack_load(INS_A(i), frame);
    record_stop(pc, frame, INS_B(i));
    return 1;
  }
  default: {
    printf("Record abort: NYI: CANT RECORD BYTECODE %s\n", ins_names[INS_OP(i)]);
    record_abort();
    return 1;
    // exit(-1);
  }
  }
  if (instr_count > 5000) {
    printf("Record abort: due to length\n");
    record_abort();
    return 1;
  }
  // if (depth <= -3) {
  //   printf("Record stop [possible down-recursion]\n");
  //   return 1;
  // }
  // TODO check chain for down-recursion
  // TODO this should check regs depth
  if (depth >= 100) {
    printf("Record abort: (stack too deep)\n");
    record_abort();
    return 1;
  }
  return 0;
}

trace_s *trace_cache_get(unsigned int tnum) { return traces[tnum]; }
