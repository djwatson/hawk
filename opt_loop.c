#include "opt_loop.h"

#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "fold.h"
#include "runtime.h"
#include "types.h"

typedef struct {
  uint16_t slot;
  slot entry;
  slot exit;
  slot steady;
  bool has_entry;
  bool has_exit;
} loop_slot;

typedef struct {
  snap sn;
  snap_entry *entries;
} copied_snap;

typedef struct {
  slot lhs;
} phi_candidate;

static bool same_slot(slot a, slot b) { return memcmp(&a, &b, sizeof(a)) == 0; }

static uint8_t slot_type(trace *t, slot v) {
  return v.constant ? get_type_tag(t->consts[v.loc]) : t->ins[v.loc].type;
}

static loop_slot *find_loop_slot(loop_slot *slots, uint16_t slot_id) {
  arr_for_each_idx(slots, i) {
    if (slots[i].slot == slot_id) {
      return &slots[i];
    }
  }
  return nullptr;
}

static loop_slot *add_loop_slot(loop_slot **slots, uint16_t slot_id) {
  loop_slot *s = find_loop_slot(*slots, slot_id);
  if (s) {
    return s;
  }
  arrput(*slots, ((loop_slot){.slot = slot_id}));
  return arrlast(*slots);
}

static bool has_stack_store_to(trace *t, uint16_t slot_id) {
  arr_for_each(t->ins, in) {
    if (in.op == IR_STACK_STORE && in.op2.constant &&
        t->consts[in.op2.loc].value == (int64_t)slot_id * 8) {
      return true;
    }
  }
  return false;
}

static slot append_raw(trace *t, ir_ins in) {
  uint16_t idx = arrlen(t->ins);
  arrput(t->cse_prev, t->cse_head[in.op]);
  t->cse_head[in.op] = idx;
  arrput(t->ins, in);
  return (slot){.constant = false, .loc = idx};
}

static bool guard_fails(trace *t, ir_ins *in) {
  if (in->op > IR_GTE || !in->op1.constant || !in->op2.constant)
    return false;
  gc_obj a = t->consts[in->op1.loc], b = t->consts[in->op2.loc];
  bool ordered = true;
  int cmp = (in->type == FIXNUM_TAG || in->type == FLONUM_TAG) &&
                    (is_fixnum(a) || is_flonum(a)) &&
                    (is_fixnum(b) || is_flonum(b))
                ? numeric_real_compare(a, b, &ordered)
                : (a.value > b.value) - (a.value < b.value);
  switch (in->op) {
  case IR_EQ: return !ordered || cmp != 0;
  case IR_NE: return ordered && cmp == 0;
  case IR_LT: return !ordered || cmp >= 0;
  case IR_GT: return !ordered || cmp <= 0;
  case IR_LTE: return !ordered || cmp > 0;
  case IR_GTE: return !ordered || cmp < 0;
  default: return false;
  }
}

static slot append_folded(trace *t, ir_ins in, bool *ok) {
  if (in.op == IR_TYPECHECK && slot_type(t, in.op1) == in.type &&
      (in.op1.constant || !in.guard || t->ins[in.op1.loc].guard))
    return in.op1;
  // Keep stores and allocation effects in both iterations.
  if (in.op == IR_STORE || in.op == IR_STORE_CHAR ||
      in.op == IR_STORE_WIDE_CHAR || in.op == IR_STORE_BYTE ||
      in.op == IR_GCLOG || in.op == IR_BOX_FLONUM)
    return append_raw(t, in);
  if (guard_fails(t, &in)) {
    *ok = false;
    return (slot){};
  }
  fold_result res = fold_instr(t, &in);
  if (guard_fails(t, &in))
    *ok = false;
  switch (res.action) {
  case FOLD_DROP:
    return (slot){.loc = 0x7fff};
  case FOLD_CONST:
    return trace_add_const(t, res.constant);
  case FOLD_REF:
    return res.ref;
  default:
    return append_raw(t, in);
  }
}

static slot subst_slot(slot *subst, slot v) {
  return v.constant ? v : subst[v.loc];
}

static ir_ins subst_ins(slot *subst, ir_ins in) {
  switch (ir_ins_types[in.op]) {
  case IR_ARG_IR_IR:
  case IR_ARG_IR_ADDR:
    in.op1 = subst_slot(subst, in.op1);
    in.op2 = subst_slot(subst, in.op2);
    break;
  case IR_ARG_IR_NONE:
    in.op1 = subst_slot(subst, in.op1);
    break;
  default:
    break;
  }
  in.reg = REG_NONE;
  in.spill = SPILL_NONE;
  return in;
}

static bool slot_is_loop_carried(loop_slot *slots, phi_candidate *phis, slot v) {
  if (v.constant) {
    return false;
  }
  arr_for_each(phis, phi) {
    if (same_slot(phi.lhs, v))
      return true;
  }
  arr_for_each(slots, s) {
    slot lhs = s.has_exit ? s.exit : s.entry;
    if (!lhs.constant && lhs.loc == v.loc) {
      return true;
    }
  }
  return false;
}

static bool ins_uses_loop_carried(loop_slot *slots, phi_candidate *phis,
                                   ir_ins *in) {
  switch (ir_ins_types[in->op]) {
  case IR_ARG_IR_IR:
  case IR_ARG_IR_ADDR:
    return slot_is_loop_carried(slots, phis, in->op1) ||
           slot_is_loop_carried(slots, phis, in->op2);
  case IR_ARG_IR_NONE:
    return slot_is_loop_carried(slots, phis, in->op1);
  default:
    return false;
  }
}

static bool substitute_loopback_sload(loop_slot *slots, ir_ins *in,
                                      slot *out) {
  if (in->op != IR_SLOAD) {
    return false;
  }
  loop_slot *s = find_loop_slot(slots, in->data);
  if (!s || !s->has_exit || s->has_entry) {
    return false;
  }
  *out = s->exit;
  return true;
}

static bool add_phi_candidate(phi_candidate **phis, slot lhs) {
  if (lhs.constant) {
    return false;
  }
  arr_for_each(*phis, phi) {
    if (same_slot(phi.lhs, lhs)) {
      return false;
    }
  }
  arrput(*phis, ((phi_candidate){.lhs = lhs}));
  return true;
}

static snap_entry *copy_entries(trace *t, snap *sn) {
  snap_entry *entries = nullptr;
  auto src = snap_entries_const(t, sn);
  for (size_t i = 0; i < snap_nent(sn); i++) {
    arrput(entries, src[i]);
  }
  return entries;
}

static void append_snap(trace *t, snap old, snap_entry *entries, slot *subst) {
  old.ir = arrlen(t->ins);
  old.mapofs = arrlen(t->snapmap);
  old.patch_point = (label){};
  old.side_exit_jcc_locs = nullptr;
  old.trace = t;
  old.nent = arrlen(entries);
  for (size_t i = 0; i < arrlen(entries); i++) {
    snap_entry entry = entries[i];
    entry.val = subst_slot(subst, entry.val);
    arrput(t->snapmap, entry);
  }
  arrput(t->snaps, old);
}

static void append_loop_snap(trace *t, snap old, snap_entry *entries,
                             snap_entry *loop_entries, slot *subst) {
  old.ir = arrlen(t->ins);
  old.mapofs = arrlen(t->snapmap);
  old.patch_point = (label){};
  old.side_exit_jcc_locs = nullptr;
  old.trace = t;
  // Unchanged sparse slots inherit the state after the pre-roll, not after
  // the copied iteration (which may not have computed their values yet).
  size_t j = 0;
  arr_for_each(entries, entry) {
    while (j < arrlen(loop_entries) && loop_entries[j].slot < entry.slot)
      arrput(t->snapmap, loop_entries[j++]);
    if (j < arrlen(loop_entries) && loop_entries[j].slot == entry.slot)
      j++;
    entry.val = subst_slot(subst, entry.val);
    arrput(t->snapmap, entry);
  }
  while (j < arrlen(loop_entries))
    arrput(t->snapmap, loop_entries[j++]);
  old.nent = (uint16_t)(arrlen(t->snapmap) - old.mapofs);
  arrput(t->snaps, old);
}

static void free_copied_snaps(copied_snap *snaps) {
  arr_for_each(snaps, sn) { arrfree(sn.entries); }
  arrfree(snaps);
}

static bool compatible_loop_slots(trace *t, loop_slot *slots) {
  arr_for_each(slots, s) {
    if (s.has_entry && s.has_exit &&
        (slot_type(t, s.entry) != slot_type(t, s.exit) ||
         (s.entry.constant && !same_slot(s.entry, s.exit)))) {
      return false;
    }
    if (s.has_entry && !s.has_exit && has_stack_store_to(t, s.slot)) {
      return false;
    }
    slot lhs = s.has_exit ? s.exit : s.entry;
    slot rhs = s.has_exit ? s.exit : (slot){};
    if ((!s.has_exit || !same_slot(lhs, rhs)) && lhs.constant) {
      return false;
    }
  }
  return true;
}

void opt_loop(trace *t) {
  if (t->link != t || t->parent_snap || arrlen(t->snaps) < 2 ||
      arrlast(t->snaps)->offset != 0 || t->link_entry_snap >= arrlen(t->snaps)) {
    return;
  }

  uint16_t body_start = t->snaps[t->link_entry_snap].ir;
  uint16_t original_nins = arrlen(t->ins);
  if (body_start >= original_nins) {
    return;
  }

  snap entry_snap = t->snaps[t->link_entry_snap];
  snap exit_snap = *arrlast(t->snaps);
  if (entry_snap.argcnt != exit_snap.argcnt) {
    return;
  }
  snap_entry *entry_entries = copy_entries(t, &entry_snap);
  snap_entry *exit_entries = copy_entries(t, &exit_snap);
  copied_snap *body_snaps = nullptr;
  loop_slot *slots = nullptr;
  phi_candidate *phis = nullptr;

  for (size_t i = 0; i < arrlen(t->snaps) - 1; i++) {
    if (t->snaps[i].ir >= body_start && t->snaps[i].ir < original_nins) {
      arrput(body_snaps,
             ((copied_snap){.sn = t->snaps[i],
                            .entries = copy_entries(t, &t->snaps[i])}));
    }
  }

  for (size_t i = 0; i < arrlen(entry_entries); i++) {
    loop_slot *s = add_loop_slot(&slots, entry_entries[i].slot);
    s->entry = entry_entries[i].val;
    s->has_entry = true;
  }
  for (size_t i = 0; i < arrlen(exit_entries); i++) {
    loop_slot *s = add_loop_slot(&slots, exit_entries[i].slot);
    s->exit = exit_entries[i].val;
    s->has_exit = true;
  }
  if (!compatible_loop_slots(t, slots)) {
    goto out;
  }

  size_t original_nsnaps = arrlen(t->snaps);
  size_t original_nconsts = arrlen(t->consts);
  uint16_t cse_head[IR_INS_MAX];
  memcpy(cse_head, t->cse_head, sizeof(cse_head));
  bool ok = true, optimized = false;
  arrpop(t->snaps);
  arrlen_set(t->snapmap, exit_snap.mapofs);

  slot *subst = malloc(sizeof(slot) * arrlen(t->ins));
  if (!subst) {
    abort();
  }
  for (uint16_t i = 0; i < arrlen(t->ins); i++) {
    subst[i] = (slot){.constant = false, .loc = i};
  }

  arr_for_each_idx(slots, i) {
    loop_slot *s = &slots[i];
    if (s->has_entry && !s->has_exit) {
      s->steady = append_raw(t, (ir_ins){.op = IR_SLOAD,
                                         .type = slot_type(t, s->entry),
                                         .reg = REG_NONE,
                                         .spill = SPILL_NONE,
                                         .data = s->slot});
    }
    if (s->has_entry && s->has_exit && !s->entry.constant) {
      subst[s->entry.loc] = s->exit;
    }
  }

  append_raw(t, (ir_ins){.op = IR_LOOP, .reg = REG_NONE, .spill = SPILL_NONE});
  t->loop_body_ir = arrlen(t->ins);
  size_t snap_idx = 0;
  for (uint16_t i = body_start; i < original_nins; i++) {
    while (snap_idx < arrlen(body_snaps) && body_snaps[snap_idx].sn.ir == i) {
      append_loop_snap(t, body_snaps[snap_idx].sn,
                       body_snaps[snap_idx].entries, exit_entries, subst);
      snap_idx++;
    }
    ir_ins in = subst_ins(subst, t->ins[i]);
    // Substitution can put a constant on the left even when folding is skipped.
    if ((in.op <= IR_GTE || in.op == IR_ADD || in.op == IR_MUL) &&
        in.op1.constant && !in.op2.constant) {
      slot tmp = in.op1;
      in.op1 = in.op2;
      in.op2 = tmp;
      if (in.op >= IR_LT && in.op <= IR_GTE)
        in.op = (ir_ins_op)(in.op ^ 1);
    }
    if (substitute_loopback_sload(slots, &in, &subst[i])) {
      if (slot_type(t, subst[i]) != in.type ||
          (in.guard && !subst[i].constant && !t->ins[subst[i].loc].guard))
        goto rollback;
      optimized = true;
      continue;
    }
    size_t before = arrlen(t->ins);
    subst[i] = ins_uses_loop_carried(slots, phis, &in) ? append_raw(t, in)
                                                 : append_folded(t, in, &ok);
    if (!ok || arrlen(t->ins) >= 0x7ffe)
      goto rollback;
    if (arrlen(t->ins) == before &&
        (in.op <= IR_ABC || in.op == IR_SLOAD || in.op == IR_LOAD ||
         in.op == IR_GGET || in.op == IR_TYPECHECK))
      optimized = true;
    if (!subst[i].constant && subst[i].loc < original_nins &&
        subst[i].loc != i) {
      add_phi_candidate(&phis, subst[i]);
    }
  }
  while (snap_idx < arrlen(body_snaps) &&
         body_snaps[snap_idx].sn.ir == original_nins) {
    append_loop_snap(t, body_snaps[snap_idx].sn, body_snaps[snap_idx].entries,
                     exit_entries, subst);
    snap_idx++;
  }
  append_snap(t, exit_snap, exit_entries, subst);
  // Do not duplicate a loop unless refolding removes a load or guard.
  if (!optimized)
    goto rollback;

  arr_for_each(slots, s) {
    slot lhs = s.has_exit ? s.exit : s.entry;
    slot rhs = s.has_exit ? subst_slot(subst, s.exit) : s.steady;
    if (!same_slot(lhs, rhs)) {
      add_phi_candidate(&phis, lhs);
    }
  }
  arr_for_each(phis, phi) {
    slot rhs = subst_slot(subst, phi.lhs);
    if (!same_slot(phi.lhs, rhs)) {
      if (slot_type(t, phi.lhs) != slot_type(t, rhs) ||
          arrlen(t->ins) >= 0x7ffe)
        goto rollback;
      append_raw(t, (ir_ins){.op = IR_PHI,
                             .type = slot_type(t, phi.lhs),
                             .reg = REG_NONE,
                             .spill = SPILL_NONE,
                             .op1 = phi.lhs,
                             .op2 = rhs});
    }
  }

  free(subst);
  goto out;
rollback:
  // Re-emission never changes pre-roll instructions: stores bypass DSE.
  arrlen_set(t->ins, original_nins);
  arrlen_set(t->cse_prev, original_nins);
  arrlen_set(t->consts, original_nconsts);
  memcpy(t->cse_head, cse_head, sizeof(cse_head));
  arrlen_set(t->snaps, original_nsnaps);
  *arrlast(t->snaps) = exit_snap;
  arrlen_set(t->snapmap, exit_snap.mapofs);
  arr_for_each(exit_entries, entry) { arrput(t->snapmap, entry); }
  t->loop_body_ir = UINT16_MAX;
  free(subst);
out:
  arrfree(phis);
  arrfree(slots);
  free_copied_snaps(body_snaps);
  arrfree(entry_entries);
  arrfree(exit_entries);
}
