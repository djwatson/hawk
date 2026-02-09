#include "fold.h"

#include <stdint.h>
#include <stdlib.h>

#include "array.h"
#include "gc.h"

typedef fold_result (*fold_func_type)(trace *t, ir_ins *in);

static fold_result fold_next(void) {
  return (fold_result){.action = FOLD_NEXT};
}
static fold_result fold_drop(void) {
  return (fold_result){.action = FOLD_DROP};
}
static fold_result fold_const(gc_obj constant) {
  return (fold_result){.action = FOLD_CONST, .constant = constant};
}

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

// If the inputs are always const, no need to guard anything!
IRFOLD(GUARD_EQ CONST CONST)
IRFOLD(NE CONST CONST)
IRFOLDF(fold_guard_const_const) { return fold_drop(); }

IRFOLD(SUB CONST CONST)
IRFOLDF(fold_sub_const_const) {
  auto lhs = t->consts[in->op1.loc];
  auto rhs = t->consts[in->op2.loc];
  if (in->type == FLONUM_TAG) {
    auto res = (flonum_s *)gc_alloc(sizeof(flonum_s));
    res->header.type = FLONUM_TAG;
    res->x = to_flonum(lhs)->x - to_flonum(rhs)->x;
    return fold_const(tag_flonum(res));
  }
  auto diff = to_fixnum(lhs) - to_fixnum(rhs);
  return fold_const(tag_fixnum(diff));
}

IRFOLD(ADD CONST CONST)
IRFOLDF(fold_add_const_const) {
  auto lhs = t->consts[in->op1.loc];
  auto rhs = t->consts[in->op2.loc];
  if (in->type == FLONUM_TAG) {
    auto res = (flonum_s *)gc_alloc(sizeof(flonum_s));
    res->header.type = FLONUM_TAG;
    res->x = to_flonum(lhs)->x + to_flonum(rhs)->x;
    return fold_const(tag_flonum(res));
  }
  auto diff = to_fixnum(lhs) + to_fixnum(rhs);
  return fold_const(tag_fixnum(diff));
}

IRFOLD(ADD CONST _)
IRFOLDF(fold_add_const_any) {
  slot tmp = in->op1;
  in->op1 = in->op2;
  in->op2 = tmp;
  return (fold_result){.action = FOLD_RETRY};
}

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
      if (res.action != FOLD_NEXT) {
        return res;
      }
    }
    if (any == 0xffff) {
      return fold_next();
    }
    any = (any | (any >> 8)) ^ 0xff00;
  }
}

fold_result fold_instr(trace *trace, ir_ins *in) {
  for (;;) {
    fold_result res = fold_one(trace, in);
    if (res.action == FOLD_RETRY) {
      continue;
    }
    return res;
  }
}
