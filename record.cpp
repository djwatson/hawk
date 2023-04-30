#include "bytecode.h"

unsigned int* pc_start;
unsigned int instr_count;

void record_start(unsigned int* pc) {
  printf("Record start\n");
  pc_start = pc;
  instr_count = 0;
}

int record_instr(unsigned int* pc) {
  instr_count++;
  unsigned int i = *pc;
  printf("Record code %s %i %i %i\n", ins_names[INS_OP(i)], INS_A(i), INS_B(i), INS_C(i));
  if (instr_count > 5000) {
    printf("Record stop due to length\n");
    return 1;
  }
  if (pc == pc_start) {
    printf("Record stop loop\n");
    return 1;
  }
  return 0;
}
