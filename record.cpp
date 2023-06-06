#include <assert.h>
#include <string.h>

#include "asm_x64.h"
#include "bytecode.h"
#include "ir.h"
#include "record.h"
#include "snap.h"
#include "types.h"
#include "vm.h"

void opt_loop(trace_s * trace, int* regs);

unsigned int *pc_start;
unsigned int instr_count;
int depth = 0;

long func;
int regs_list[257];
int *regs = &regs_list[1];
snap_s *side_exit = NULL;
trace_s *parent = NULL;

std::vector<unsigned int *> downrec;

enum trace_state_e {
  OFF = 0,
  START,
  TRACING,
};

trace_state_e trace_state = OFF;
trace_s *trace = NULL;
std::vector<trace_s *> traces;

unsigned int *patchpc = NULL;
unsigned int patchold;

void pendpatch() {
  if (patchpc) {
    printf("PENDPACTCH\n");
    *patchpc = patchold;
    patchpc = NULL;
  }
}

void print_const_or_val(int i, trace_s *ctrace) {
  if (i & IR_CONST_BIAS) {
    auto c = ctrace->consts[i - IR_CONST_BIAS];
    int type = c & 0x7;
    if (c & SNAP_FRAME) {
      printf("(pc %li)", c & ~SNAP_FRAME);
    } else if (type == 0) {
      printf("\e[1;35m%li\e[m", c >> 3);
    } else if (type == 5) {
      printf("\e[1;31m<closure>\e[m");
    } else if (c == FALSE_REP) {
      printf("\e[1;35m#f\e[m");
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
    while ((cur_snap < ctrace->snaps.size()) && ctrace->snaps[cur_snap].ir == i) {
      
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
           op.type & IR_INS_TYPE_GUARD ? '>' : ' ');
    auto t = op.type & ~IR_INS_TYPE_GUARD;
    if (t == 0) {
      printf("\e[1;35mfix\e[m ");
    } else if (t == 5) {
      printf("\e[1;31mclo\e[m ");
    } else {
      printf("\e[1;34mUNK\e[m ");
    }
    printf("%s ", ir_names[(int)op.op]);
    switch (op.op) {
    case ir_ins_op::KFIX:
    case ir_ins_op::SLOAD: {
      print_const_or_val(op.op1, ctrace);
      break;
    }
    case ir_ins_op::GGET: {
      symbol *s = (symbol *)ctrace->consts[op.op1 - IR_CONST_BIAS];
      printf("%s", s->name->str);
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
    case ir_ins_op::CLT: {
      print_const_or_val(op.op1, ctrace);
      printf(" ");
      print_const_or_val(op.op2, ctrace);
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
  printf("Record start %i at %s func %s\n", trace->num, ins_names[INS_OP(*pc)], ((bcfunc*)func)->name.c_str());
  if (parent) {
    printf("Parent %i\n", parent->num);
  }
  pc_start = pc;
  trace->startpc = *pc;
  instr_count = 0;
  depth = 0;
  regs = &regs_list[1];
  for (int i = 0; i < 257; i++) {
    regs_list[i] = -1;
  }

  if (side_exit) {
    snap_replay(&regs, side_exit, parent, trace, frame, &depth);
  }
  add_snap(regs_list, regs - regs_list - 1, trace,
           INS_OP(*pc) == FUNC ? pc + 1 : pc);
}

extern int joff;

void record_stop(unsigned int *pc, long *frame, int link) {
  auto offset = regs - regs_list - 1;
  add_snap(regs_list, offset, trace, pc);
  if(link == (int)traces.size() && offset == 0) {
    // Attempt to loop-fiy it.
    opt_loop(trace, regs);
  }
  
  pendpatch();

  if (side_exit) {
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

  assign_registers(trace);
  dump_trace(trace);
  asm_jit(trace, side_exit, parent);
  if (side_exit) {
    uint64_t *patchpoint = (uint64_t *)side_exit->patchpoint;
    *patchpoint = uint64_t(trace->fn);
  }

  trace_state = OFF;
  side_exit = NULL;
  downrec.clear();
  // joff = 1;
}

void record_abort() {
  pendpatch();
  delete trace;
  trace_state = OFF;
  side_exit = NULL;
  downrec.clear();
}

int record(unsigned int *pc, long *frame) {
  if (traces.size() >= 200) {
    return 1;
  }
  switch (trace_state) {
  case OFF: {
    // TODO fix?
    if (INS_OP(*pc) == JFUNC && side_exit == NULL) {
      // printf("CAN'T RECORD TO JFUNC\n");
      return 1;
    }
    record_start(pc, frame);
    auto res = record_instr(pc, frame);
    if (trace_state == START) {
      trace_state = TRACING;
    }
    return res;
    break;
  }
  case TRACING: {
    pendpatch();
    auto res = record_instr(pc, frame);
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

int record_stack_load(int slot, long *frame) {
  if (regs[slot] == -1) {
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op1 = slot;
    ins.op = ir_ins_op::SLOAD;
    // Guard on type
    auto type = frame[slot] & 0x7;
    ins.type = IR_INS_TYPE_GUARD | type;

    regs[slot] = trace->ops.size();
    trace->ops.push_back(ins);
  }
  return regs[slot];
}

extern unsigned char hotmap[hotmap_sz];
int record_instr(unsigned int *pc, long *frame) {
  instr_count++;
  unsigned int i = *pc;
  if (INS_OP(i) == LOOP) {
    for(int* pos = &regs[INS_A(i)]; pos < &regs_list[257]; pos++) {
      *pos = -1;
    }
  }
  if ((pc == pc_start) && (depth == 0) && (trace_state == TRACING) &&
      INS_OP(trace->startpc) != RET1) {
    printf("Record stop loop\n");
    record_stop(pc, frame, traces.size());
    return 1;
  }
  for (int j = 0; j < depth; j++) {
    printf(" . ");
  }
  printf("%lx %s %i %i %i\n", (long)pc, ins_names[INS_OP(i)], INS_A(i), INS_B(i),
         INS_C(i));
  switch (INS_OP(i)) {
  case LOOP:
  case CLFUNC:
  case FUNC: {
    // TODO: argcheck?
    break;
  }
  case RET1: {
    if (depth == 0) {
      auto old_pc = (unsigned int *)frame[-1];
      if (INS_OP(*pc_start) == RET1 || side_exit != NULL) {
        int cnt = 0;
        for (auto &p : downrec) {
          if (p == pc) {
            cnt++;
          }
        }
        if (cnt) {
          if (side_exit) {
            printf("Potential down-recursion, restarting\n");
            record_abort();
            record_start(pc, frame);
            record_instr(pc, frame);
            trace_state = TRACING;
            break;
          }
          printf("Record stop downrec\n");
          record_stop(pc, frame, traces.size());
          return 1;
        }
        downrec.push_back(pc);

        // Guard down func type
        add_snap(regs_list, regs - regs_list - 1, trace, pc);

        auto frame_off = INS_A(*(old_pc - 1));
        printf("Continue down recursion, frame offset %i\n", frame_off);
        auto result = record_stack_load(INS_A(i), frame);
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

        add_snap(regs_list, regs - regs_list - 1, trace, pc);
        // TODO retdepth
      } else {
        printf("Record stop return\n");
        record_stop(pc, frame, -1);
        // record_abort();
        return 1;
      }
    } else if (depth > 0) {
      depth--;
      regs[-1] = regs[INS_A(i)];
      for (int j = regs - regs_list; j < 257; j++) {
        regs_list[j] = -1;
      }
      auto old_pc = (unsigned int *)frame[-1];
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
    for (unsigned j = INS_A(i)+1; j < INS_A(i) + INS_B(i); j++) {
      regs[j] = record_stack_load(j, frame);
    }

    // Check call type
    {
      auto v = frame[INS_A(i)+1];
      auto knum = trace->consts.size();
      trace->consts.push_back(v);
      ir_ins ins;
      ins.reg = REG_NONE;
      ins.op1 = record_stack_load(INS_A(i)+1, frame);
      ins.op2 = knum | IR_CONST_BIAS;
      ins.op = ir_ins_op::EQ;
      // TODO magic number
      ins.type = IR_INS_TYPE_GUARD | 0x5;
      trace->ops.push_back(ins);
    }
    long cnt = 0;
    auto p_pc = (uint32_t *)frame[-1];
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
      auto v = frame[INS_A(i)+1];
      auto closure = (closure_s *)(v - CLOSURE_TAG);
      auto cfunc = (bcfunc *)closure->v[0];
      auto target = &cfunc->code[0];
      if (target == pc_start) {
        printf("Record stop up-recursion\n");
        record_stop(pc, frame, traces.size());
        return 1;
      } else {
        // TODO fix flush
        pendpatch();
        if (INS_OP(cfunc->code[0]) == JFUNC) {
          printf("Flushing trace\n");
          cfunc->code[0] = traces[INS_D(cfunc->code[0])]->startpc;
          hotmap[(((long)pc) >> 2) & hotmap_mask] = 1;
        }
        // TODO this isn't in luajit? fails with side exit without?
        hotmap[(((long)pc) >> 2) & hotmap_mask] = 1;
        record_abort();
        printf("Record abort unroll limit reached\n");
        return 1;
      }
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
    add_snap(regs_list, regs - regs_list - 1, trace, pc);
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op1 = record_stack_load(INS_B(i), frame);
    ins.op2 = record_stack_load(INS_C(i), frame);
    if (frame[INS_B(i)] < frame[INS_C(i)]) {
      ins.op = ir_ins_op::LT;
    } else {
      ins.op = ir_ins_op::GE;
    }
    ins.type = IR_INS_TYPE_GUARD;
    trace->ops.push_back(ins);
    break;
  }
  case JISEQ: {
    add_snap(regs_list, regs - regs_list - 1, trace, pc);
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op1 = record_stack_load(INS_B(i), frame);
    ins.op2 = record_stack_load(INS_C(i), frame);
    if (frame[INS_B(i)] == frame[INS_C(i)]) {
      ins.op = ir_ins_op::EQ;
    } else {
      ins.op = ir_ins_op::NE;
    }
    ins.type = IR_INS_TYPE_GUARD;
    trace->ops.push_back(ins);
    break;
  }
  case MOV: {
    regs[INS_A(i)] = record_stack_load(INS_B(i), frame);
    // TODO loop moves can clear
    //regs[INS_B(i)] = -1;
    break;
  }
  case GGET: {
    long gp = (const_table[INS_D(i)] - SYMBOL_TAG);
    auto knum = trace->consts.size();
    trace->consts.push_back(gp);
    ir_ins ins;
    ins.reg = REG_NONE;
    ins.op1 = knum | IR_CONST_BIAS;
    ins.op = ir_ins_op::GGET;
    ins.type = IR_INS_TYPE_GUARD | (((symbol *)gp)->val & 0x7);
    auto reg = INS_A(i);
    regs[reg] = trace->ops.size();
    trace->ops.push_back(ins);
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
    ins.type = IR_INS_TYPE_GUARD | trace->ops[ins.op1].type;
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
    ins.type = IR_INS_TYPE_GUARD | trace->ops[ins.op1].type;
    auto reg = INS_A(i);
    regs[reg] = trace->ops.size();
    trace->ops.push_back(ins);
    break;
  }
  case CALLT: {
    // Check call type
    {
      auto v = frame[INS_A(i)+1];
      auto knum = trace->consts.size();
      trace->consts.push_back(v);
      ir_ins ins;
      ins.reg = REG_NONE;
      ins.op1 = record_stack_load(INS_A(i)+1, frame);
      ins.op2 = knum | IR_CONST_BIAS;
      ins.op = ir_ins_op::EQ;
      // TODO magic number
      ins.type = IR_INS_TYPE_GUARD | 0x5;
      trace->ops.push_back(ins);
    }
    // Move args down
    // TODO also chedck func
    for (unsigned j = INS_A(i)+1; j < INS_A(i) + INS_B(i); j++) {
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
    auto ctrace = trace_cache_get(INS_B(i));
    if (ctrace->link == -1) {
      assert(patchpc == NULL);
      patchpc = pc;
      patchold = *pc;
      *pc = traces[INS_D(*pc)]->startpc;
      break;
    } else {
      for (unsigned j = 0; j < INS_A(i); j++) {
        regs[j] = record_stack_load(j, frame);
      }
      printf("Record stop JFUNC\n");
      record_stop(pc, frame, INS_B(i));
      return 1;
    }
  }
  case JLOOP: {
    if (side_exit == NULL) {
      printf("Record stop root trace hit loop\n");
      record_abort();
      return 1;
    } else {
      printf("Record stop hit JLOOP\n");
      regs[INS_A(i)] = record_stack_load(INS_A(i), frame);
      record_stop(pc, frame, INS_B(i));
      return 1;
    }
  }
  default: {
    printf("NYI: CANT RECORD BYTECODE %s\n", ins_names[INS_OP(i)]);
    record_abort();
    return 1;
    //exit(-1);
  }
  }
  if (instr_count > 5000) {
    record_abort();
    printf("Record abort due to length\n");
    return 1;
  }
  // if (depth <= -3) {
  //   printf("Record stop [possible down-recursion]\n");
  //   return 1;
  // }
  // TODO check chain for down-recursion
  // TODO this should check regs depth
  if (depth >= 100) {
    record_abort();
    printf("Record abort (stack too deep)\n");
    return 1;
  }
  return 0;
}

trace_s *trace_cache_get(unsigned int tnum) { return traces[tnum]; }
