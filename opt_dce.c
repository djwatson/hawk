// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include "opt_dce.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "array.h"
#include "hawk.h"

static void mark_snaps(trace *trace, bool *marks) {
  for (uint64_t i = 0; i < arrlen(trace->snaps); i++) {
    auto sn = &trace->snaps[i];
    auto entries = snap_entries(trace, sn);
    for (uint64_t j = 0; j < snap_nent(sn); j++) {
      auto sslot = &entries[j];
      if (!sslot->val.constant) {
        marks[sslot->val.loc] = true;
      }
    }
  }
}

static bool mark_value(bool *marks, slot value) {
  if (value.constant || marks[value.loc]) return false;
  marks[value.loc] = true;
  return true;
}

static bool *live_phis(trace *t) {
  size_t n = arrlen(t->ins);
  bool *live = calloc(n, sizeof(bool));
  if (t->loop_body_ir == UINT16_MAX) return live;
  for (size_t i = 0; i < arrlen(t->snaps); i++) {
    auto sn = &t->snaps[i];
    if (sn->ir < t->loop_body_ir) continue;
    auto entries = snap_entries(t, sn);
    for (size_t j = 0; j < snap_nent(sn); j++)
      mark_value(live, entries[j].val);
  }
  bool changed;
  do {
    changed = false;
    for (size_t i = n; i > t->loop_body_ir; i--) {
      auto in = &t->ins[i - 1];
      if (in->op == IR_PHI) {
        if (live[in->op1.loc]) {
          live[i - 1] = true;
          changed |= mark_value(live, in->op2);
        }
      } else if (live[i - 1] || ir_sideeff(in->op) || in->guard) {
        auto type = ir_ins_types[in->op];
        if (type == IR_ARG_IR_NONE || type == IR_ARG_IR_IR)
          changed |= mark_value(live, in->op1);
        if (type == IR_ARG_IR_IR)
          changed |= mark_value(live, in->op2);
      }
    }
  } while (changed);
  return live;
}

static void propagate(trace *t, bool *marks) {
  bool *phis = live_phis(t);
  bool changed;
  do {
    changed = false;
    for (size_t i = arrlen(t->ins); i > 0; i--) {
      auto in = &t->ins[i - 1];
      if (in->op == IR_PHI) {
        if (phis[i - 1]) {
          marks[i - 1] = true;
          changed |= mark_value(marks, in->op1);
          changed |= mark_value(marks, in->op2);
        }
        continue;
      }
      if (ir_sideeff(in->op) || in->guard) marks[i - 1] = true;
      if (!marks[i - 1]) continue;
      auto type = ir_ins_types[in->op];
      if (type == IR_ARG_IR_NONE || type == IR_ARG_IR_IR)
        changed |= mark_value(marks, in->op1);
      if (type == IR_ARG_IR_IR)
        changed |= mark_value(marks, in->op2);
    }
  } while (changed);
  free(phis);
  for (size_t i = 0; i < arrlen(t->ins); i++) {
    if (!marks[i]) {
      t->ins[i].op = IR_NOP;
      t->ins[i].guard = false;
    }
  }
}

void dce(trace *trace) {
  size_t ins_len = arrlen(trace->ins);
  if (ins_len == 0) {
    return;
  }

  bool *marks = calloc(ins_len, sizeof(bool));

  mark_snaps(trace, marks);
  propagate(trace, marks);

  free(marks);
}
