#include "fold.h"

#include <stdint.h>
#include <stdlib.h>

#include "array.h"

typedef enum fold_result {
  FOLD_NEXT,
  FOLD_RETRY,
} fold_result;

typedef fold_result (*fold_func_type)(trace *t, ir_ins *in);

static uint8_t fold_arg(trace *t, ir_ins *in, uint8_t idx) {
  auto arg_type = ir_ins_types[in->op];
  if (idx == 0 && (arg_type == IR_ARG_IR_NONE || arg_type == IR_ARG_IR_IR)) {
    return in->op1.constant ? FOLD_ARG_CONST : t->ins[in->op1.loc].op;
  }
  if (idx == 1 && arg_type == IR_ARG_IR_IR) {
    return in->op2.constant ? FOLD_ARG_CONST : t->ins[in->op2.loc].op;
  }
  return FOLD_ARG_ANY;
}

static uint32_t fold_key(trace *t, ir_ins *in) {
  uint32_t key = in->op << 16;
  key |= fold_arg(t, in, 0) << 8;
  key |= fold_arg(t, in, 1);
  return key;
}

#define IRFOLD(x)
#define IRFOLDX(x)
#define IRFOLDF(name)                                                          \
  static fold_result name(trace *t __attribute__((unused)),                    \
                          ir_ins *in __attribute__((unused)))
#define cur_ins (*in)

IRFOLD(GUARD_EQ _ _)
IRFOLDF(fold_guard_const_const) { abort(); }

#undef cur_ins

#include "fold_gen.h"

static fold_result fold_one(trace *t, ir_ins *in) {
  uint32_t key = fold_key(t, in);
  uint32_t any = 0;
  for (;;) {
    uint32_t k = key | any;
    uint32_t h = hashkey(k);
    uint32_t fh = fold_hash[h];
    if ((fh & 0xffffff) == k) {
      auto res = fold_func_table[fh >> 24](t, in);
      if (res != FOLD_NEXT) {
        return res;
      }
    }
    if (any == 0xffff) {
      return FOLD_NEXT;
    }
    any = (any | (any >> 8)) ^ 0xff00;
  }
}

void fold_instr(trace *trace, ir_ins *in) {
  while (fold_one(trace, in) == FOLD_RETRY) {
  }
}

void fold_trace(trace *trace) {
  for (size_t i = 0; i < arrlen(trace->ins); i++) {
    fold_instr(trace, &trace->ins[i]);
  }
}
