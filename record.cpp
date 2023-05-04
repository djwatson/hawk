#include <string.h>
#include <assert.h>

#include "record.h"
#include "bytecode.h"
#include "ir.h"
#include "snap.h"

unsigned int *pc_start;
unsigned int instr_count;
int depth = 0;

static long stack[256]; // TODO just walk the stack.
long func;
int regs_list[257];
int* regs =&regs_list[1];
snap_s* side_exit = NULL;
trace_s* parent = NULL;

std::vector<unsigned int*> downrec;

enum trace_state_e {
  OFF=0,
  START,
  TRACING,
};

trace_state_e trace_state = OFF;
trace_s* trace = NULL;
std::vector<trace_s*> traces;

unsigned int *patchpc = NULL;
unsigned int patchold;

void pendpatch() {
  if (patchpc) {
    *patchpc = patchold;
    patchpc = NULL;
  }
}

void print_const_or_val(int i, trace_s* trace) {
  if(i&IR_CONST_BIAS) {
    auto c = trace->consts[i - IR_CONST_BIAS];
    int type = c&0x7;
    if (c&SNAP_FRAME) {
      printf("(pc %li)", c&~SNAP_FRAME);
    } else if (type == 0) {
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
  int cur_snap = 0;
  for(int i = 0; i < trace->ops.size() +1 /* extra snap */; i++) {
    // Print any snap
    while ((cur_snap < trace->snaps.size()) &&
	trace->snaps[cur_snap].ir == i) {
      auto& snap = trace->snaps[cur_snap];
      printf("SNAP[pc=%i off=%i", snap.pc, snap.offset);
      for(auto& entry : snap.slots) {
	printf(" %i=", entry.slot);
	print_const_or_val(entry.val, trace);
      }
      printf("]\n");
      cur_snap++;
    }
    if (i == trace->ops.size()) {
      break;
    }
    
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
    case ir_ins_op::RET: 
    case ir_ins_op::SUB:
    case ir_ins_op::ADD:
    case ir_ins_op::EQ:
    case ir_ins_op::NE:
    case ir_ins_op::GE:
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

void record_side(trace_s* p, snap_s* side) {
  parent = p;
  side_exit = side;
}

void record_start(unsigned int *pc, long *frame) {
 trace = new trace_s;
  trace_state = START;
  func = frame[-1]-5;
  printf("Record start at %s\n", ins_names[INS_OP(*pc)]);
  pc_start = pc;
  trace->startpc = *pc;
  instr_count = 0;
  depth = 0;
  regs = &regs_list[1];
  for(int i = 0; i < 257; i++) {
    regs_list[i] = -1;
  }

  if (side_exit) {
    snap_replay(&regs, side_exit, parent, trace, frame, &depth);
  }
}

extern int joff;

void record_stop(unsigned int *pc, long *frame, int link) {
  pendpatch();
  
  auto func = (bcfunc*)(frame[-1]-5);
  int32_t pcloc= (long)(pc - &func->code[0]);
  add_snap(regs_list, regs-regs_list - 1, trace, pcloc);
  if (side_exit) {
    side_exit->link = traces.size();
  } else {
    if (INS_OP(*pc_start) == FUNC) {
      *pc_start = CODE(JFUNC, 0, traces.size(), 0);
    } else {
      *pc_start = CODE(JLOOP, 0, traces.size(), 0);
    }
  }
  printf("Installing trace %li\n", traces.size());
  dump_trace(trace);
  trace->link = link;
  traces.push_back(trace);
  trace_state = OFF;
  side_exit = NULL;
  downrec.clear();
  //joff = 1;
}

void record_abort() {
  delete trace;
  trace_state = OFF;
  side_exit = NULL;
  downrec.clear();
}

int record(unsigned int *pc, long *frame) {
  if (traces.size() > 255) {
    return 1;
  }
  switch (trace_state) {
  case OFF: {
    // TODO fix?
    if (INS_OP(*pc) == JFUNC) {
      printf("CAN'T RECORD TO JFUNC\n");
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
  auto func = (bcfunc*)(frame[-1]-5);
  int32_t pcloc= (long)(pc - &func->code[0]);
  instr_count++;
  unsigned int i = *pc;
  if ((pc == pc_start) && (depth == 0) && (trace_state == TRACING)) {
    record_stop(pc, frame, traces.size());
    printf("Record stop loop\n");
    return 1;
  }
  for(int j = 0; j < depth; j++) {
    printf(" . ");
  }
  printf("%s %i %i %i\n", ins_names[INS_OP(i)], INS_A(i),
         INS_B(i), INS_C(i));
  switch (INS_OP(i)) {
  case FUNC: {
    // TODO: argcheck?
    break;
  }
  case RET1: {
    if (depth == 0) {
      auto old_pc = (unsigned int *)frame[-2];
      auto old_frame = frame - (INS_A(*(old_pc-1)) + 2);
      auto old_target = (bcfunc*)(old_frame[-1]-5);
      if(INS_OP(*pc_start) == RET1 || side_exit != NULL) {
	int cnt = 0;
	for(auto& p: downrec) {
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
	add_snap(regs_list, regs-regs_list - 1, trace, pcloc);

	auto frame_off = INS_A(*(old_pc-1));
	printf("Continue down recursion, frame offset %i\n", frame_off);
	auto result = record_stack_load(INS_A(i), frame);
	memmove(&regs[frame_off+2], &regs[0], sizeof(int)*(256 - (frame_off+2)));
	regs[frame_off] = result;
	for(int i = 0; i < frame_off; i++) {
	  regs[i] = -1;
	}
	
	auto knum = trace->consts.size();
	trace->consts.push_back((long)old_pc|SNAP_FRAME);
	auto knum2 = trace->consts.size();
	trace->consts.push_back((frame_off+2) << 3);
	ir_ins ins;
	ins.op1 = knum|IR_CONST_BIAS;
	// TODO this isn't a runtime const?  can gen directly from PC?
	ins.op2 = knum2|IR_CONST_BIAS;
	ins.op = ir_ins_op::RET;
	ins.type = IR_INS_TYPE_GUARD|0x5;
	trace->ops.push_back(ins);

	// TODO retdepth
      } else {
	record_stop(pc, frame, -1);
	//record_abort();
	printf("Record stop return\n");
	return 1;
      }
    } else if (depth > 0) {
      depth--;
      regs[-2] = regs[INS_A(i)];
      for(int i= regs-regs_list -1; i<257; i++) {
	regs_list[i] = -1;
      }
      auto old_pc = (unsigned int *)frame[-2];
      regs -= (INS_A(*(old_pc - 1)) + 2);
    } else {
      depth--;
      printf("TODO return below trace\n");
      exit(-1);
    }
    break;
  }
  case CALL: {
    stack[depth] = frame[INS_A(i) + 1];
    auto func = (bcfunc*)(frame[INS_A(i)+1]-5);
    auto target = &func->code[0];
    // Check for call unroll
    auto f = stack[depth];
    long cnt = 0;
    for (int j = depth; j >= 0; j--) {
      if (stack[j] == f) {
        cnt++;
      }
    }
    if (cnt >= 3) {
      if (target == pc_start) {
        record_stop(pc, frame, traces.size());
        printf("Record stop up-recursion\n");
        return 1;
      } else {
	auto func = (bcfunc*)(frame[INS_A(i) + 1] - 5) /*tag*/;
	if (INS_OP(func->code[0]) == JFUNC) {
	  printf("Flushing trace\n");
	  func->code[0] = (func->code[0]&~0xff) | FUNC;
	}
        record_abort();
        printf("Record abort unroll limit reached\n");
        return 1;
      }
    }
    depth++;
    // Check call type
    {
      auto v = frame[INS_A(i)+1];
      auto knum = trace->consts.size();
      trace->consts.push_back(v);
      ir_ins ins;
      ins.op1 = record_stack_load(INS_A(i)+1, frame);
      ins.op2 = knum | IR_CONST_BIAS;
      ins.op = ir_ins_op::EQ;
      // TODO magic number
      ins.type = IR_INS_TYPE_GUARD | 0x5;
      trace->ops.push_back(ins);
    }
    // Push PC link as const
    auto knum = trace->consts.size();
    trace->consts.push_back(((long)(pc + 1)) | SNAP_FRAME);
    regs[INS_A(i)] = knum | IR_CONST_BIAS;     // TODO set PC

    // Increment regs
    regs += INS_A(i) + 2;
    break;
  }
  case KSHORT: {
    auto k = INS_BC(i) << 3;
    auto knum = trace->consts.size();
    auto reg = INS_A(i);
    regs[reg] = trace->consts.size() | IR_CONST_BIAS;
    trace->consts.push_back(k);
    break;
  }
  case JISLT: {
    add_snap(regs_list, regs-regs_list - 1, trace, pcloc);
    ir_ins ins;
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
    add_snap(regs_list, regs-regs_list - 1, trace, pcloc);
    ir_ins ins;
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
    regs[INS_B(i)] = record_stack_load(INS_A(i), frame);
    break;
  }
  case GGET: {
    bcfunc *func = (bcfunc *)(frame[-1]-5);
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
  case ADDVN: {
    ir_ins ins;
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
      // TODO magic number
      ins.type = IR_INS_TYPE_GUARD | 0x5;
      trace->ops.push_back(ins);
    }
    // Move args down
    // TODO also chedck func
    memmove(&regs[-1], &regs[INS_A(i)], sizeof(int)*(INS_B(i)));
    // if (func == (bcfunc*)(frame[INS_A(i)])) {
    //   // No need to save same tailcalled.
    //   regs[-1] = -1;
    // }
    for(int j = INS_B(i)-1; j < 256; j++) {
      if (&regs[j] >= regs_list+256) {
	break;
      }
      regs[j] = -1;
    }

    break;
  }
  case JMP: {
    // None.
    break;
  }
  case JFUNC: {
    // Check if it is a returning trace
    auto trace = trace_cache_get(INS_B(i));
    if (trace->link == -1) {
      assert(patchpc == NULL);
      patchpc = pc;
      patchold = *pc;
      *pc = ((*pc)&~0xff)|FUNC;
      break;
    } else {
      record_stop(pc, frame, INS_B(i));
      printf("Record stop JFUNC\n");
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
      record_stop(pc, frame, INS_B(i));
      return 1;
    }
  }
  default: {
    printf("NYI: CANT RECORD BYTECODE %s\n", ins_names[INS_OP(i)]);
    exit(-1);
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

trace_s* trace_cache_get(unsigned int tnum) {
  return traces[tnum];
}
