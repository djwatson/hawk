#include "ir.h"

char *ir_names[] = {
#define X(name) #name,
  IR_OPS
  #undef X
};

void print_ir(trace* t) {
  for(int i = 0; i < arrlen_ins(t->ins); i++) {
    ir_ins* ins = &t->ins[i];
    printf("%i: %s\n", i, ir_names[ins->op]);
  }
}
