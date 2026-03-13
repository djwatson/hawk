// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include "box_closure_flonums.h"

#include <assert.h>
#include <stdlib.h>

#include "array.h"

// * bug: storing an unboxed flonum to a closure/cons can result in GC
//   seeing a partially initialized object, since we box in the middle
//   of object initialization

static slot remap_slot(slot s, int32_t *old_to_new) {
  if (s.constant) {
    return s;
  }
  assert(old_to_new[s.loc] >= 0);
  return (slot){.constant = false, .loc = (uint16_t)old_to_new[s.loc]};
}

static void remap_ins(ir_ins *ins, int32_t *old_to_new) {
  switch (ir_ins_types[ins->op]) {
  case IR_ARG_IR_IR:
    ins->op1 = remap_slot(ins->op1, old_to_new);
    ins->op2 = remap_slot(ins->op2, old_to_new);
    break;
  case IR_ARG_IR_NONE:
  case IR_ARG_IR_ADDR:
    ins->op1 = remap_slot(ins->op1, old_to_new);
    break;
  default:
    break;
  }
}

static bool is_hoist_alloc(trace *trace, uint16_t idx) {
  auto ins = &trace->ins[idx];
  if (ins->op != IR_ALLOC || !ins->op2.constant ||
      !is_fixnum(trace->consts[ins->op2.loc])) {
    return false;
  }
  auto tag = to_fixnum(trace->consts[ins->op2.loc]);
  return tag == CLOSURE_TAG || tag == CONS_TAG;
}

static bool is_hoist_store(trace *trace, uint16_t idx, uint16_t alloc_idx) {
  auto store = &trace->ins[idx];
  if (store->op != IR_STORE || store->op1.constant || store->op2.constant) {
    return false;
  }
  auto ref = &trace->ins[store->op1.loc];
  return ref->op == IR_REF && !ref->op1.constant && ref->op1.loc == alloc_idx &&
         trace->ins[store->op2.loc].type == FLONUM_TAG;
}

static slot hoist_before_alloc(trace *trace, slot v, uint16_t alloc_idx,
                               ir_ins **new_ins, int32_t *old_to_new,
                               int32_t *hoisted) {
  if (v.constant || v.loc < alloc_idx) {
    return remap_slot(v, old_to_new);
  }
  if (hoisted[v.loc] >= 0) {
    return (slot){.constant = false, .loc = (uint16_t)hoisted[v.loc]};
  }

  ir_ins clone = trace->ins[v.loc];
  switch (clone.op) {
  case IR_ALLOC:
  case IR_STORE:
  case IR_GSET:
  case IR_RET:
  case IR_PMOV:
  case IR_ARG:
    abort();
  default:
    break;
  }

  remap_ins(&clone, old_to_new);
  switch (ir_ins_types[clone.op]) {
  case IR_ARG_IR_IR:
    clone.op1 = hoist_before_alloc(trace, trace->ins[v.loc].op1, alloc_idx,
                                   new_ins, old_to_new, hoisted);
    clone.op2 = hoist_before_alloc(trace, trace->ins[v.loc].op2, alloc_idx,
                                   new_ins, old_to_new, hoisted);
    break;
  case IR_ARG_IR_NONE:
  case IR_ARG_IR_ADDR:
    clone.op1 = hoist_before_alloc(trace, trace->ins[v.loc].op1, alloc_idx,
                                   new_ins, old_to_new, hoisted);
    break;
  default:
    break;
  }
  clone.reg = REG_NONE;
  clone.spill = SPILL_NONE;

  uint16_t new_idx = (uint16_t)arrlen(*new_ins);
  arrput(*new_ins, clone);
  hoisted[v.loc] = new_idx;
  return (slot){.constant = false, .loc = new_idx};
}

void box_closure_flonums(trace *trace) {
  size_t ins_len = arrlen(trace->ins);
  if (ins_len == 0) {
    return;
  }

  int32_t *old_to_new = malloc(ins_len * sizeof(int32_t));
  int32_t *hoisted = malloc(ins_len * sizeof(int32_t));
  bool *rewrite_store = calloc(ins_len, sizeof(bool));
  slot *rewritten_vals = malloc(ins_len * sizeof(slot));
  if (!old_to_new || !hoisted || !rewrite_store || !rewritten_vals) {
    abort();
  }
  for (size_t i = 0; i < ins_len; i++) {
    old_to_new[i] = -1;
    hoisted[i] = -1;
  }

  ir_ins *new_ins = nullptr;
  for (uint16_t i = 0; i < ins_len; i++) {
    if (is_hoist_alloc(trace, i)) {
      for (size_t j = i + 1; j < ins_len; j++) {
        if (!is_hoist_store(trace, (uint16_t)j, i)) {
          continue;
        }
        auto src = hoist_before_alloc(trace, trace->ins[j].op2, i, &new_ins,
                                      old_to_new, hoisted);
        uint16_t box_idx = (uint16_t)arrlen(new_ins);
        arrput(new_ins, ((ir_ins){.op = IR_BOX_FLONUM,
                                  .type = UNDEFINED_TAG,
                                  .reg = REG_NONE,
                                  .spill = SPILL_NONE,
                                  .op1 = src}));
        rewrite_store[j] = true;
        rewritten_vals[j] = (slot){.constant = false, .loc = box_idx};
      }
    }

    ir_ins ins = trace->ins[i];
    remap_ins(&ins, old_to_new);
    if (rewrite_store[i]) {
      ins.op2 = rewritten_vals[i];
    }
    uint16_t new_idx = (uint16_t)arrlen(new_ins);
    arrput(new_ins, ins);
    old_to_new[i] = new_idx;
  }

  arrfree(trace->ins);
  trace->ins = new_ins;

  arr_for_each_idx(trace->snaps, snap_idx) {
    auto snap = &trace->snaps[snap_idx];
    if (snap->ir == ins_len) {
      snap->ir = (uint16_t)arrlen(trace->ins);
    } else {
      snap->ir = (uint16_t)old_to_new[snap->ir];
    }
    arr_for_each_idx(snap->slots, entry_idx) {
      auto entry = &snap->slots[entry_idx];
      if (!entry->val.constant) {
        entry->val.loc = (uint16_t)old_to_new[entry->val.loc];
      }
    }
  }

  free(old_to_new);
  free(hoisted);
  free(rewrite_store);
  free(rewritten_vals);
}
