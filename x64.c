#include "x64.h"

#include "asm_x64.h"

uint8_t callee_save[] = {RBX, RBP, R12, R13, R14, R15};

void restore_callee_regs() {
  for (uint8_t i = 0; i < 5; i++) {
    emit_pop(callee_save[i]);
  }
}
void save_callee_regs() {
  for (uint8_t i = 5; i > 0; i--) {
    emit_push(callee_save[i - 1]);
  }
}
