#include <string.h>

#include "record.h"
#include "bytecode.h"
#include "ir.h"

unsigned int *pc_start;
unsigned int instr_count;
int depth = 0;

static long stack[256]; // TODO just walk the stack.
long func;
int regs[256];

struct trace_s {
  std::vector<ir_ins> ops;
  std::vector<long> consts;
};

enum trace_state_e {
  OFF,
  START,
  TRACING,
};

trace_state_e trace_state = OFF;
trace_s* trace = NULL;
std::vector<trace_s*> traces;

void print_const_or_val(int i, trace_s* trace) {
  if(i&IR_CONST_BIAS) {
    auto c = trace->consts[i - IR_CONST_BIAS];
    int type = c&0x7;
    if (type == 0) {
      printf("\e[1;35m%li\e[m", c >> 3);
    } else if (type == 5) {
      printf("\e[1;31m<closure>\e[m");
    } else {
      printf("Unknown dump_trace type %i\n", type);
      exit(-1);
    }
  } else {
    printf("%04d", i);
  }
}

void dump_trace(trace_s* trace) {
  for(int i = 0; i < trace->ops.size(); i++) {
    auto op = trace->ops[i];
    printf("%04d %c\t",i,
	   op.type & IR_INS_TYPE_GUARD ? '>' : ' ');
    auto t = op.type & ~IR_INS_TYPE_GUARD;
    if(t == 0) {
      printf("\e[1;35mfix\e[m ");
    } else if(t==5) {
      printf("\e[1;31mclo\e[m ");
    } else {
      printf("\e[1;34mUNK\e[m ");
    }
    printf("%s ",
	   ir_names[(int)op.op]);
    switch(op.op) {
    case ir_ins_op::KFIX: 
    case ir_ins_op::SLOAD: {
      print_const_or_val(op.op1, trace);
      break;
    }
    case ir_ins_op::GGET: {
      symbol* s = (symbol*)trace->consts[op.op1-IR_CONST_BIAS];
      printf("%s", s->name.c_str());
      break;
    }
    case ir_ins_op::SUB:
    case ir_ins_op::ADD:
    case ir_ins_op::EQ:
    case ir_ins_op::LT: {
      print_const_or_val(op.op1, trace);
      printf(" ");
      print_const_or_val(op.op2, trace);
      break;
    }
    default:
      printf("Can't dump_trace ir type: %s\n", ir_names[(int)op.op]);
      exit(-1);
    }
    printf("\n");
  }
}

void record_start(unsigned int *pc, long *frame) {
  trace = new trace_s;
  trace_state = START;
  func = frame[-1];
  printf("Record start at %s\n", ins_names[INS_OP(*pc)]);
  pc_start = pc;
  instr_count = 0;
  depth = 0;
  for(int i = 0; i < 256; i++) {
    regs[i] = -1;
  }
}

void record_stop(unsigned int *pc, long *frame) {
  *pc_start = CODE(JFUNC, 0, traces.size(), 0);
  dump_trace(trace);
  traces.push_back(trace);
  trace_state = OFF;
}

void record_abort() {
  delete trace;
  trace_state = OFF;
}

int record(unsigned int *pc, long *frame) {
  switch (trace_state) {
  case OFF: {
    record_start(pc, frame);
    auto res = record_instr(pc, frame);
    if (trace_state == START) {
      trace_state = TRACING;
    }
    return res;
    break;
  }
  case TRACING: {
    return record_instr(pc, frame);
    break;
  }
  default: {
    printf("BAD TRACE STATE\n");
    exit(-1);
    return 1;
  }
  }
}

int record_stack_load(int slot, long *frame) {
  if (regs[slot] == -1) {
    ir_ins ins;
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

int record_instr(unsigned int *pc, long *frame) {
  // TODO working on snap
  // for(int i = 0; i < 256; i++) {
  //   if (regs[i] != -1) {
  //     printf("MOV %i %i\n", regs[i], i);
  //   }
  // }
  instr_count++;
  unsigned int i = *pc;
  if ((pc == pc_start) && (depth == 0) && (trace_state == TRACING)) {
    record_stop(pc, frame);
    printf("Record stop loop\n");
    return 1;
  }
    printf("%i Record code %s %i %i %i\n", depth, ins_names[INS_OP(i)], INS_A(i),
         INS_B(i), INS_C(i));
  switch (INS_OP(i)) {
  case RET1:
  case RET: {
    if (depth == 0) {
      record_abort();
      printf("Record stop return\n");
      return 1;
    }
    depth--;
    printf("TODO othe return\n");
    exit(-1);
    break;
  }
  case CALL: {
    stack[depth] = frame[INS_A(i) + 1];
    // Check for call unroll
    auto f = stack[depth];
    long cnt = 0;
    for (int j = depth; j >= 0; j--) {
      if (stack[j] == f) {
        cnt++;
      }
    }
    if (cnt >= 3) {
      if (pc == pc_start) {
        record_abort();
        printf("Record stop up-recursion\n");
        return 1;
      } else {
        record_abort();
        printf("Record stop unroll limit reached\n");
        return 1;
      }
    }
    depth++;
    printf("TODO rec call\n");
    exit(-1);
    break;
  }
  case KSHORT: {
    auto k = INS_BC(i) << 3;
    auto knum = trace->consts.size();
    trace->consts.push_back(k << 3);
    auto reg = INS_A(i);
    regs[reg] = k | IR_CONST_BIAS;
    break;
  }
  case JISLT: {
    ir_ins ins;
    ins.op1 = record_stack_load(INS_B(i), frame);
    ins.op2 = record_stack_load(INS_C(i), frame);
    ins.op = ir_ins_op::LT;
    ins.type = IR_INS_TYPE_GUARD;
    trace->ops.push_back(ins);
    break;
  }
  case GGET: {
    bcfunc *func = (bcfunc *)frame[-1];
    long gp = func->consts[INS_B(i)];
    auto knum = trace->consts.size();
    trace->consts.push_back(gp);
    ir_ins ins;
    ins.op1 = knum | IR_CONST_BIAS;
    ins.op = ir_ins_op::GGET;
    ins.type = IR_INS_TYPE_GUARD | (((symbol*)gp)->val&0x7);
    auto reg = INS_A(i);
    regs[reg] = trace->ops.size();
    trace->ops.push_back(ins);
    break;
  }
  case SUBVN: {
    ir_ins ins;
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
  case ADDVV: {
    ir_ins ins;
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
  case CALLT: {
    // Check call type
    {
      auto v = frame[INS_A(i)];
      auto knum = trace->consts.size();
      trace->consts.push_back(v);
      ir_ins ins;
      ins.op1 = record_stack_load(INS_A(i), frame);
      ins.op2 = knum | IR_CONST_BIAS;
      ins.op = ir_ins_op::EQ;
      // TODO magic
      ins.type = IR_INS_TYPE_GUARD | 0x5;
      trace->ops.push_back(ins);
    }
    // Move args down
    memmove(&regs[0], &regs[INS_A(i)], sizeof(regs) - (sizeof(int)*INS_A(i)));
    break;
  }
  case JMP: {
    // None.
    break;
  }
  default: {
    printf("NYI: CANT RECORD BYTECODE %s\n", ins_names[INS_OP(i)]);
    exit(-1);
  }
  }
  if (instr_count > 5000) {
    record_abort();
    printf("Record stop due to length\n");
    return 1;
  }
  // if (depth <= -3) {
  //   printf("Record stop [possible down-recursion]\n");
  //   return 1;
  // }
  // TODO check chain for down-recursion
  if (depth >= 100) {
    record_abort();
    printf("Record stop (stack too deep)\n");
    return 1;
  }
  return 0;
}

void record_run(unsigned int tnum, unsigned int **o_pc, long **o_frame,
                long *frame_top) {}
