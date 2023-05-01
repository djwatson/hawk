#include "bytecode.h"
#include "record.h"

unsigned int *pc_start;
unsigned int instr_count;
int depth = 0;

static long stack[256];
std::vector<unsigned int> trace_buffer;
std::vector<std::vector<unsigned int>> traces;
long func;

enum trace_state_e{
  OFF,
  START,
  TRACING,
};

trace_state_e trace_state = OFF;

void record_start(unsigned int *pc, long*frame) {
  trace_state = START;
  func = frame[-1];
  printf("Record start at %s\n", ins_names[INS_OP(*pc)]);
  pc_start = pc;
  instr_count = 0;
  depth = 0;
  trace_buffer.clear();
}

void record_stop(unsigned int *pc, long *frame) {
  auto trace = traces.size();
  traces.push_back(std::move(trace_buffer));
  trace_buffer.clear();
  *pc_start = CODE(JFUNC, 0, trace, 0);
  trace_state = OFF;
}

void record_abort() {
  trace_buffer.clear();
  trace_state = OFF;
}

int record(unsigned int *pc, long *frame) {
  switch(trace_state) {
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

int record_instr(unsigned int *pc, long *frame) {
  instr_count++;
  unsigned int i = *pc;
  trace_buffer.push_back(i);
  printf("%i Record code %s %i %i %i\n", depth, ins_names[INS_OP(i)], INS_A(i),
         INS_B(i), INS_C(i));
  if (INS_OP(i) == RET || INS_OP(i) == RET1) {
    if (depth == 0) {
      record_abort();
      printf("Record stop return\n");
      return 1;
    }
    depth--;
  }
  if (INS_OP(i) == CALL) {
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
  }
  if (instr_count > 5000) {
    record_abort();
    printf("Record stop due to length\n");
    return 1;
  }
  if ((pc == pc_start) && (depth == 0) && (trace_state == TRACING)) {
    record_stop(pc, frame);
    printf("Record stop loop\n");
    return 1;
  }
  // if (depth <= -3) {
  //   printf("Record stop [possible down-recursion]\n");
  //   return 1;
  // }
  // TODO check chain for down-recursion
  if (depth >= 256) {
    record_abort();
    printf("Record stop (stack too deep)\n");
    return 1;
  }
  return 0;
}


//////////////////// runner

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
static void FAIL_SLOWPATH(long a, long b) {
  printf("TRACE ABORT\n");
  exit(-1);
}
static long ADDVV_SLOWPATH(long a, long b) {
  printf("ADDVV ABORT\n");
  exit(-1);
}
static void EXPAND_STACK_SLOWPATH() {
  printf("STACK ABORT\n");
  exit(-1);
}
static void UNDEFINED_SYMBOL_SLOWPATH(symbol* gp) {
  printf("UNDEFINED ABORT\n");
  exit(-1);
}
extern std::vector<bcfunc *> funcs;
// TODO also return frame
void record_run(unsigned int tnum, unsigned int** o_pc, long** o_frame, long* frame_top) {
  std::vector<unsigned int> trace = traces[tnum];
  long* frame = *o_frame;

  unsigned int *pc = &trace[0];

  // clang-format off
  void* l_op_table[] = {
    NULL,
    &&L_INS_KSHORT,
    &&L_INS_ISGE,
    &&L_INS_JMP,
    &&L_INS_RET1,
    &&L_INS_SUBVN,
    &&L_INS_CALL,
    &&L_INS_ADDVV,
    &&L_INS_HALT,
    &&L_INS_ALLOC,
    &&L_INS_ISLT, //10
    &&L_INS_ISF,
    &&L_INS_SUBVV,
    &&L_INS_GGET,
    &&L_INS_GSET,
    &&L_INS_KFUNC,
    &&L_INS_CALLT,
    &&L_INS_KONST,
    &&L_INS_MOV,
    &&L_INS_ISEQ,
    &&L_INS_ADDVN, //20
    &&L_INS_JISEQ,
    &&L_INS_JISLT,
    &&L_INS_JFUNC,
  };

  //#define DIRECT {i = *pc; goto *l_op_table[INS_OP(i)];}
#define DIRECT
  while (true) {
    unsigned int i = *pc;
    #ifdef DEBUG
    printf("Running PC %li code %s %i %i %i\n", pc - &trace[0], ins_names[INS_OP(i)],
           INS_A(i), INS_B(i), INS_C(i));
    printf("frame %li: %li %li %li %li\n", frame - stack, frame[0], frame[1],
           frame[2], frame[3]);
    #endif

    goto *l_op_table[INS_OP(i)];

    switch (INS_OP(i)) {
    case 1: {
    L_INS_KSHORT:
      frame[INS_A(i)] = INS_BC(i) << 3;
      pc++;
      DIRECT;
      break;
    }
    case 2: {
    L_INS_ISGE:
      long fa = frame[INS_A(i)];
      long fb = frame[INS_B(i)];
      if (unlikely(1 & (fa | fb))) {
        FAIL_SLOWPATH(fa, fb);
      }
      if (fa >= fb) {
        pc += 1;
      } else {
        pc += 2;
      }
      DIRECT;
      break;
    }
    case 21: {
    L_INS_JISEQ:
      long fb = frame[INS_B(i)];
      long fc = frame[INS_C(i)];
      if (unlikely(1 & (fc | fb))) {
        FAIL_SLOWPATH(fb, fc);
      }
      if (fb == fc) {
        pc += 2;
      } else {
        pc += 1;
      }
      DIRECT;
      break;
    }
    case 22: {
    L_INS_JISLT:
      long fb = frame[INS_B(i)];
      long fc = frame[INS_C(i)];
      if (unlikely(1 & (fc | fb))) {
        FAIL_SLOWPATH(fb, fc);
      }
      // TODO
      if (fb < fc) {
	*o_frame = frame;
	return;
      } else {
	pc++;
      }
      DIRECT;
      break;
    }
    case 10: {
    L_INS_ISLT:
      long fb = frame[INS_B(i)];
      long fc = frame[INS_C(i)];
      if (unlikely(1 & (fc | fb))) {
        FAIL_SLOWPATH(fb, fc);
      }
      // TODO true/false
      if (fb < fc) {
        frame[INS_A(i)] = 1;
      } else {
        frame[INS_A(i)] = 0;
      }
      pc++;
      DIRECT;
      break;
    }
    case 19: {
    L_INS_ISEQ:
      long fb = frame[INS_B(i)];
      long fc = frame[INS_C(i)];
      if (unlikely(1 & (fc | fb))) {
        FAIL_SLOWPATH(fb, fc);
      }
      // TODO true/false
      if (fb == fc) {
        frame[INS_A(i)] = 1;
      } else {
        frame[INS_A(i)] = 0;
      }
      pc++;
      DIRECT;
      break;
    }
    case 11: {
    L_INS_ISF:
      // TODO false
      if (0 == frame[INS_A(i)]) {
        pc += 1;
      } else {
        pc += 2;
      }
      DIRECT;
      break;
    }
    case 3: {
    L_INS_JMP:
      pc++;
      DIRECT;
      break;
    }
    case 4: {
    L_INS_RET1:
      pc = (unsigned int *)frame[-2];
      frame[-2] = frame[INS_A(i)];
      frame -= (INS_A(*(pc - 1)) + 2);
      DIRECT;
      break;
    }
    case 5: {
    L_INS_SUBVN:
      long fb = frame[INS_B(i)];
      if (unlikely(1 & fb)) {
        FAIL_SLOWPATH(fb, 0);
      }
      if (unlikely(
              __builtin_sub_overflow(fb, (INS_C(i) << 3), &frame[INS_A(i)]))) {
        FAIL_SLOWPATH(fb, 0);
      }
      pc++;
      DIRECT;
      break;
    }
    case 20: {
    L_INS_ADDVN:
      long fb = frame[INS_B(i)];
      if (unlikely(1 & fb)) {
        FAIL_SLOWPATH(fb, 0);
      }
      if (unlikely(
              __builtin_add_overflow(fb, (INS_C(i) << 3), &frame[INS_A(i)]))) {
        FAIL_SLOWPATH(fb, 0);
      }
      pc++;
      DIRECT;
      break;
    }
    case 6: {
    L_INS_CALL:
      auto v = frame[INS_A(i) + 1];
      if (unlikely((v & 0x7) != 5)) {
        FAIL_SLOWPATH(v, 0);
      }
      bcfunc *func = (bcfunc *)(v - 5);
      frame[INS_A(i) + 1] = (long)func;
      auto old_pc = pc;
      pc = &func->code[0];
      frame[INS_A(i)] = (long)(old_pc + 1);
      if (unlikely((frame + 256 + 2 + INS_A(i)) > frame_top)) {
        EXPAND_STACK_SLOWPATH();
      }
      frame += INS_A(i) + 2;
      DIRECT;
      break;
    }
    case 16: {
    L_INS_CALLT:
      pc = &trace[0];
      long start = INS_A(i) + 1;
      auto cnt = INS_B(i) - 1;
      for (auto i = 0; i < cnt; i++) {
        frame[i] = frame[start + i];
      }
      DIRECT;
      break;
    }

    case 7: {
    L_INS_ADDVV:
      auto rb = frame[INS_B(i)];
      auto rc = frame[INS_C(i)];
      if (unlikely(1 & (rb | rc))) {
        frame[INS_A(i)] = ADDVV_SLOWPATH(rb, rc);
      } else {
        if (unlikely(__builtin_add_overflow(rb, rc, &frame[INS_A(i)]))) {
          frame[INS_A(i)] = ADDVV_SLOWPATH(rb, rc);
        }
      }
      pc++;
      DIRECT;
      break;
    }
    case 8: {
    L_INS_HALT:
      printf("Result:%li\n", frame[INS_A(i)] >> 3);
      return;
    }
    case 9: {
    L_INS_ALLOC:
      // TODO
      frame[INS_A(i)] = (long)malloc(INS_B(i));
      break;
    }
    case 12: {
    L_INS_SUBVV:
      long rb = frame[INS_B(i)];
      long rc = frame[INS_C(i)];
      if (unlikely(1 & (rb | rc))) {
        frame[INS_A(i)] = ADDVV_SLOWPATH(rb, rc);
      } else {
        if (unlikely(__builtin_sub_overflow(rb, rc, &frame[INS_A(i)]))) {
          FAIL_SLOWPATH(rb, rc);
        }
      }
      pc++;
      DIRECT;
      break;
    }
    case 13: {
    L_INS_GGET:
      bcfunc *func = (bcfunc *)frame[-1];
      symbol *gp = (symbol *)func->consts[INS_B(i)];
      if (unlikely(gp->val == UNDEFINED)) {
        UNDEFINED_SYMBOL_SLOWPATH(gp);
      }
      frame[INS_A(i)] = gp->val;
      pc++;
      DIRECT;
      break;
    }
    case 14: {
    L_INS_GSET:
      bcfunc *func = (bcfunc *)frame[-1];
      symbol *gp = (symbol *)func->consts[INS_A(i)];
      gp->val = frame[INS_B(i)];
      pc++;
      DIRECT;
      break;
    }
    case 15: {
    L_INS_KFUNC:
      bcfunc *f = funcs[INS_B(i)];
      // TODO func tag define
      frame[INS_A(i)] = ((long)f) + 5;
      pc++;
      DIRECT;
      break;
    }
    case 17: {
    L_INS_KONST:
      bcfunc *func = (bcfunc *)frame[-1];
      frame[INS_A(i)] = func->consts[INS_B(i)];
      pc++;
      DIRECT;
      break;
    }
    case 18: {
    L_INS_MOV:
      frame[INS_B(i)] = frame[INS_A(i)];
      pc++;
      DIRECT;
      break;
    }

    case 23: {
      L_INS_JFUNC:
      printf("JFUNC in trace\n");
      exit(-1);
      DIRECT;
      break;
    }


    default: {
      printf("Unknown instruction %i %s\n", INS_OP(i), ins_names[INS_OP(i)]);
      exit(-1);
    }
    }
  }
}

