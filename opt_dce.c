// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include "opt_dce.h"

#include <stdio.h>
#include <stdlib.h>

#include "array.h"
#include "hawk.h"

static void mark_snaps(trace *trace, bool *marks) {
  for (uint64_t i = 0; i < arrlen(trace->snaps); i++) {
    auto snap = &trace->snaps[i];
    for (uint64_t j = 0; j < arrlen(snap->slots); j++) {
      auto sslot = &snap->slots[j];
      if (!sslot->val.constant) {
        marks[sslot->val.loc] = true;
      }
    }
  }
}

static void propagate(trace *trace, bool *marks) {
  for (uint64_t i = arrlen(trace->ins); i > 0; i--) {
    auto ins = &trace->ins[i - 1];
    if ((ins->op == IR_IFT || ins->op == IR_IFF) &&
        trace->ins[ins->a1.loc].op <= IR_FL_GT && !marks[ins->a1.loc]) {
      // If the jump is the only use of a comparison, we can fold the
      // jump in to the compare.
      uint8_t prev_op = ins->op;
      *ins = trace->ins[ins->op1.loc];
      ins->type = GUARD_TAG;
      if (prev_op == IR_IFF) {
        // Flip.
        ins->op ^= 1;
      }
    }
    if (ir_sideeff(*ins)) {
      marks[i - 1] = true;
    }
    if (!marks[i - 1]) {
      if (verbose) {
        fprintf(stderr, "IR_DEAD: %lu %s\n", i - 1, ir_names[ins->op]);
      }
      ins->op = IR_DEAD;
      continue;
    }
    auto type = ir_instruction_types[ins->op];
    if ((type == IR_ARG_IR_NONE || type == IR_ARG_IR_IR) && !ins->a1.constant) {
      marks[ins->a1.loc] = true;
    }
    if (type == IR_ARG_IR_IR && !ins->a2.constant) {
      marks[ins->a2.loc] = true;
    }
  }
}

void dce(trace *trace) {
  bool *marks = calloc(arrlen(trace->ins), sizeof(bool));

  mark_snaps(trace, marks);
  propagate(trace, marks);

  free(marks);
}
