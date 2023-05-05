#include <stdio.h>
#include <stdlib.h>

#include "asm_x64.h"

int get_free_reg(int* slot) {
  for(int i=0; i < regcnt; i++) {
    if (slot[i] == -1) {
      return i;
    }
  }
  printf("ERROR no free reg\n");
  exit(-1);
}

void assign_registers(trace_s* trace) {
  int slot[regcnt];
  for(int i = 0; i < regcnt; i++) {
    slot[i] = -1;
  }
  
  for(int i = trace->ops.size()-1; i >= 0; i--) {
    auto& op = trace->ops[i];
    printf("Assign to op %s\n", ir_names[(int)op.op]);
    op.reg = get_free_reg(slot);
  }
}
