#include "bytecode.h"

unsigned int *pc_start;
unsigned int instr_count;
int depth = 0;

static long stack[256];
std::vector<unsigned int> trace_buffer;
std::vector<std::vector<unsigned int>> traces;
long func;

void record_start(unsigned int *pc, long*frame) {
  func = frame[-1];
  printf("Record start\n");
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
}

int record_instr(unsigned int *pc, long *frame) {
  instr_count++;
  unsigned int i = *pc;
  trace_buffer.push_back(i);
  printf("%i Record code %s %i %i %i\n", depth, ins_names[INS_OP(i)], INS_A(i),
         INS_B(i), INS_C(i));
  if (INS_OP(i) == RET || INS_OP(i) == RET1) {
    if (depth == 0) {
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
        printf("Record stop up-recursion\n");
        return 1;
      } else {
        printf("Record stop unroll limit reached\n");
        return 1;
      }
    }
    depth++;
  }
  if (instr_count > 5000) {
    printf("Record stop due to length\n");
    return 1;
  }
  if ((pc == pc_start) && (depth == 0)) {
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
    printf("Record stop (stack too deep)\n");
    return 1;
  }
  return 0;
}

unsigned int* record_run(unsigned int trace, long* frame) {
  return 0;
}
