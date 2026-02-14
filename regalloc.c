#include "regalloc.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asm.h"
#include "hawk.h"
#include "ir.h"

typedef struct {
  uint16_t ir_idx;
  bool before;
  bool is_snap;
  uint32_t next;
} next_use;

typedef struct regalloc2_state regalloc2_state;

static inline bool ins_uses_freg(ir_ins const *ins) {
  return ins->type == FLONUM_TAG;
}

static void collect_next_uses(regalloc2_state *s);
static void print_next_uses(regalloc2_state *s);
static dense_loc_entry lookup_loc(regalloc2_state *s, uint16_t value_id,
                                  uint16_t pos);

typedef struct {
  uint16_t start;
  uint16_t end;
} fixed_range;

typedef struct {
  uint16_t value_id;
  uint16_t start;
  uint16_t end;
  bool is_float;
  uint8_t reg;
  uint8_t hint;
  uint8_t deferred_move_from;
  uint8_t deferred_reload_spill;
} ls_interval;

typedef struct {
  uint16_t value_id;
  uint16_t start;
  uint16_t end;
  bool in_reg;
  uint8_t loc;
} value_range;

typedef struct regalloc2_state {
  trace *t;
  uint32_t *uses;
  next_use *next_uses;

  ls_interval *unhandled_intervals;
  ls_interval *active_intervals;
  ls_interval *expired_intervals;
  fixed_range *active_fixed[MAX_REG];
  fixed_range *inactive_fixed[MAX_REG];
  value_range *ranges;
  dense_loc_entry *dense_locs;
  uint16_t *ir_id_to_dense_map;
  register_op *ops;
  uint8_t next_spill;
} regalloc2_state;

typedef void (*ir_arg_callback)(slot s, void *ctx);

static void add_next_use(regalloc2_state *s, uint16_t loc, uint16_t ir_idx,
                         bool before, bool is_snap) {
  auto next = (next_use){.ir_idx = ir_idx,
                         .before = before,
                         .is_snap = is_snap,
                         .next = s->uses[loc]};
  s->uses[loc] = (uint32_t)arrlen(s->next_uses);
  arrput(s->next_uses, next);
}

static void collect_next_uses(regalloc2_state *s) {
  size_t ins_len = arrlen(s->t->ins);
  if (ins_len == 0) {
    return;
  }

  s->uses = calloc(ins_len, sizeof(uint32_t));
  assert(s->uses != NULL);

  // Use 0 as the null index in use chains.
  arrput(s->next_uses, ((next_use){0}));

  size_t snap_len = arrlen(s->t->snaps);
  size_t cur_snap = snap_len;
  uint16_t cur_snap_end_ir = ins_len;

  for (size_t i = ins_len; i > 0; i--) {
    while (cur_snap != 0 &&
           (cur_snap == snap_len || s->t->snaps[cur_snap].ir >= (i - 1))) {
      cur_snap--;
      auto cur = &s->t->snaps[cur_snap];
      arr_for_each_idx(cur->slots, slot_i) {
        auto val = cur->slots[slot_i].val;
        if (!val.constant) {
          add_next_use(s, val.loc, cur_snap_end_ir, false, true);
        }
      }
      cur_snap_end_ir = cur->ir;
    }

    auto ins = &s->t->ins[i - 1];
    switch (ir_ins_types[ins->op]) {
    case IR_ARG_IR_IR:
      if (!ins->op2.constant) {
        add_next_use(s, ins->op2.loc, (uint16_t)(i - 1), true, false);
      }
      [[fallthrough]];
    case IR_ARG_IR_NONE:
    case IR_ARG_IR_ADDR:
      if (!ins->op1.constant) {
        add_next_use(s, ins->op1.loc, (uint16_t)(i - 1), true, false);
      }
      break;
    default:
      break;
    }
  }
}

static void print_next_uses(regalloc2_state *s) {
  size_t ins_len = arrlen(s->t->ins);
  printf("next_use chains:\n");
  for (size_t i = 0; i < ins_len; i++) {
    printf("  %04zu:", i);
    uint32_t next_idx = s->uses[i];
    if (next_idx == 0) {
      printf(" <none>\n");
      continue;
    }
    while (next_idx != 0) {
      auto cur = s->next_uses[next_idx];
      printf(" %s%s@%u", cur.is_snap ? "S-" : "I-", cur.before ? "B" : "A",
             cur.ir_idx);
      next_idx = cur.next;
    }
    printf("\n");
  }
}

static void walk_ir_args(ir_ins const *ins, ir_arg_callback cb, void *ctx) {
  switch (ir_ins_types[ins->op]) {
  case IR_ARG_IR_IR:
    cb(ins->op1, ctx);
    cb(ins->op2, ctx);
    break;
  case IR_ARG_IR_NONE:
  case IR_ARG_IR_ADDR:
    cb(ins->op1, ctx);
    break;
  default:
    break;
  }
}

static inline uint16_t ir_before_pos(uint16_t ir_idx) { return ir_idx * 2; }
static inline uint16_t ir_after_pos(uint16_t ir_idx) { return ir_idx * 2 + 1; }

static inline uint16_t pos_ir(uint16_t pos) { return pos / 2; }
static inline bool pos_before(uint16_t pos) { return (pos % 2) == 0; }

static inline uint16_t use_pos(next_use n) {
  return n.before ? ir_before_pos(n.ir_idx) : ir_after_pos(n.ir_idx);
}

static dense_loc_entry lookup_loc(regalloc2_state *s, uint16_t value_id,
                                  uint16_t pos) {
  bool found = false;
  ls_interval best = {};
  for (size_t i = 0; i < arrlen(s->expired_intervals); i++) {
    auto it = s->expired_intervals[i];
    if (it.value_id != value_id) {
      continue;
    }
    if (it.start <= pos && pos <= it.end) {
      if (!found || it.end > best.end) {
        best = it;
        found = true;
      }
    }
  }

  auto ins = &s->t->ins[value_id];
  if (found) {
    if (best.reg != REG_NONE) {
      return (dense_loc_entry){.kind = LOC_REG,
                               .reg = best.reg,
                               .spill = SPILL_NONE,
                               .value_id = value_id};
    }
    assert(ins->spill != SPILL_NONE);
    return (dense_loc_entry){.kind = LOC_SPILL,
                             .reg = REG_NONE,
                             .spill = ins->spill,
                             .value_id = value_id};
  }
  assert(ins->reg != REG_NONE);
  return (dense_loc_entry){.kind = LOC_REG,
                           .reg = ins->reg,
                           .spill = SPILL_NONE,
                           .value_id = value_id};
}

static void init_fixed_intervals(regalloc2_state *s) {
  bool reserved[MAX_REG] = {0};
  asm_mark_unallocatable(reserved);
  uint16_t max_pos =
      arrlen(s->t->ins) == 0 ? 0 : (uint16_t)(arrlen(s->t->ins) * 2 - 1);
  for (int r = 0; r < MAX_REG; r++) {
    if (reserved[r]) {
      arrput(s->inactive_fixed[r], ((fixed_range){.start = 0, .end = max_pos}));
    }
  }
}

static uint8_t get_or_assign_spill_slot(regalloc2_state *s, uint16_t value_id) {
  auto ins = &s->t->ins[value_id];
  if (ins->spill != SPILL_NONE) {
    return ins->spill;
  }
  assert(s->next_spill < 255);
  ins->spill = s->next_spill++;
  return ins->spill;
}

static int add_interval(regalloc2_state *s, uint16_t value_id, uint16_t start,
                        uint16_t end) {
  auto it = (ls_interval){.value_id = value_id,
                          .start = start,
                          .end = end,
                          .is_float = ins_uses_freg(&s->t->ins[value_id]),
                          .reg = REG_NONE,
                          .hint = REG_NONE,
                          .deferred_move_from = REG_NONE,
                          .deferred_reload_spill = SPILL_NONE};
  arrput(s->unhandled_intervals, it);
  return (int)arrlen(s->unhandled_intervals) - 1;
}

static void build_intervals(regalloc2_state *s) {
  size_t ins_len = arrlen(s->t->ins);
  for (uint16_t v = 0; v < ins_len; v++) {
    auto ins = &s->t->ins[v];
    // RET with constant input needs a tmp register for existing emit path.
    if (ins->op == IR_RET && ins->op1.constant) {
      uint16_t pos = ir_before_pos(v);
      add_interval(s, v, pos, pos);
    }

    if (!s->uses[v]) {
      continue;
    }
    uint16_t start = ir_after_pos(v);
    uint16_t end = start;
    uint32_t use_idx = s->uses[v];
    while (use_idx != 0) {
      auto n = s->next_uses[use_idx];
      end = use_pos(n);
      use_idx = n.next;
    }
    auto interval = add_interval(s, v, start, end);

    if (ins->op == IR_PMOV && ins->spill == SPILL_NONE &&
        ins->reg != REG_NONE) {
      s->unhandled_intervals[interval].hint = ins->reg;
    }
  }
}

static ls_interval pop_smallest_unhandled_interval(regalloc2_state *s) {
  assert(arrlen(s->unhandled_intervals) > 0);
  size_t min_idx = 0;
  for (size_t i = 1; i < arrlen(s->unhandled_intervals); i++) {
    if (s->unhandled_intervals[i].start <
        s->unhandled_intervals[min_idx].start) {
      min_idx = i;
    }
  }

  auto out = s->unhandled_intervals[min_idx];
  size_t last_idx = arrlen(s->unhandled_intervals) - 1;
  s->unhandled_intervals[min_idx] = s->unhandled_intervals[last_idx];
  arrpop(s->unhandled_intervals);
  return out;
}

static void expire_active_intervals(regalloc2_state *s, uint16_t current_pos) {
  size_t i = 0;
  while (i < arrlen(s->active_intervals)) {
    if (s->active_intervals[i].end < current_pos) {
      arrput(s->expired_intervals, s->active_intervals[i]);
      size_t last_idx = arrlen(s->active_intervals) - 1;
      s->active_intervals[i] = s->active_intervals[last_idx];
      arrpop(s->active_intervals);
      continue;
    }
    i++;
  }
}

static void adjust_active_fixed_intervals(regalloc2_state *s,
                                          uint16_t current_pos) {
  for (int r = 0; r < MAX_REG; r++) {
    size_t i = 0;
    while (i < arrlen(s->active_fixed[r])) {
      auto range = s->active_fixed[r][i];
      assert(range.start <= current_pos);
      if (range.end < current_pos) {
        size_t last_idx = arrlen(s->active_fixed[r]) - 1;
        s->active_fixed[r][i] = s->active_fixed[r][last_idx];
        arrpop(s->active_fixed[r]);
        continue;
      }
      i++;
    }
  }
}

static void adjust_inactive_fixed_intervals(regalloc2_state *s,
                                            uint16_t current_pos) {
  for (int r = 0; r < MAX_REG; r++) {
    size_t i = 0;
    while (i < arrlen(s->inactive_fixed[r])) {
      auto range = s->inactive_fixed[r][i];
      if (range.start >= current_pos) {
        i++;
        continue;
      }
      size_t last_idx = arrlen(s->inactive_fixed[r]) - 1;
      s->inactive_fixed[r][i] = s->inactive_fixed[r][last_idx];
      arrpop(s->inactive_fixed[r]);
      if (range.end >= current_pos) {
        arrput(s->active_fixed[r], range);
      }
    }
  }
}

static void split_interval(regalloc2_state *s, ls_interval *interval,
                           uint16_t split_pos, uint8_t parent_reg) {
  assert(split_pos > interval->start);
  assert(split_pos <= interval->end);

  auto child = *interval;
  child.start = split_pos;
  child.reg = REG_NONE;
  child.deferred_move_from = parent_reg;
  child.deferred_reload_spill = SPILL_NONE;
  get_or_assign_spill_slot(s, child.value_id);
  arrput(s->unhandled_intervals, child);

  interval->end = split_pos - 1;
}

static uint16_t interval_next_use_from(regalloc2_state *s, uint16_t value_id,
                                       uint16_t from_pos) {
  uint32_t use_idx = s->uses[value_id];
  while (use_idx != 0) {
    auto n = s->next_uses[use_idx];
    uint16_t pos = use_pos(n);
    if (pos >= from_pos) {
      return pos;
    }
    use_idx = n.next;
  }
  return UINT16_MAX;
}

static uint16_t interval_next_use_after(regalloc2_state *s, uint16_t value_id,
                                        uint16_t from_pos) {
  uint32_t use_idx = s->uses[value_id];
  while (use_idx != 0) {
    auto n = s->next_uses[use_idx];
    uint16_t pos = use_pos(n);
    if (pos > from_pos) {
      return pos;
    }
    use_idx = n.next;
  }
  return UINT16_MAX;
}

static uint16_t next_inactive_fixed_start(regalloc2_state *s, uint8_t reg,
                                          uint16_t from_pos) {
  uint16_t out = UINT16_MAX;
  arr_for_each(s->inactive_fixed[reg], range) {
    if (range.start >= from_pos && range.start < out) {
      out = range.start;
    }
  }
  return out;
}

static int find_active_interval_by_reg(regalloc2_state *s, uint8_t reg) {
  for (size_t i = 0; i < arrlen(s->active_intervals); i++) {
    if (s->active_intervals[i].reg == reg) {
      return (int)i;
    }
  }
  return -1;
}

static void spill_active_interval(regalloc2_state *s, ls_interval victim,
                                  uint16_t current_pos) {
  assert(victim.reg != REG_NONE);
  uint16_t next_use = interval_next_use_after(s, victim.value_id, current_pos);
  uint8_t spill = get_or_assign_spill_slot(s, victim.value_id);

  if (next_use == UINT16_MAX || next_use > victim.end) {
    return;
  }
  arrput(s->unhandled_intervals,
         ((ls_interval){.value_id = victim.value_id,
                        .start = next_use,
                        .end = victim.end,
                        .is_float = victim.is_float,
                        .reg = REG_NONE,
                        .hint = victim.hint,
                        .deferred_move_from = REG_NONE,
                        .deferred_reload_spill = spill}));
}

typedef struct {
  uint16_t ir_idx;
  bool before;
} deferred_op_pos;

static deferred_op_pos deferred_op_position(ls_interval const *interval) {
  return (deferred_op_pos){.ir_idx = pos_ir(interval->start),
                           .before = pos_before(interval->start)};
}

static void emit_deferred_reload_if_needed(regalloc2_state *s,
                                           ls_interval *interval) {
  if (interval->deferred_reload_spill == SPILL_NONE) {
    return;
  }
  assert(interval->reg != REG_NONE);
  auto p = deferred_op_position(interval);
  arrput(s->ops, ((register_op){.ir_idx = p.ir_idx,
                                .before = p.before,
                                .kind = REGISTER_OP_RELOAD,
                                .value_id = interval->value_id,
                                .reg = interval->reg,
                                .src_reg = REG_NONE,
                                .spill = interval->deferred_reload_spill}));
  interval->deferred_reload_spill = SPILL_NONE;
}

static void emit_deferred_move_if_needed(regalloc2_state *s,
                                         ls_interval *interval) {
  if (interval->deferred_move_from == REG_NONE) {
    return;
  }
  assert(interval->reg != REG_NONE);
  auto p = deferred_op_position(interval);
  get_or_assign_spill_slot(s, interval->value_id);
  arrput(s->ops, ((register_op){.ir_idx = p.ir_idx,
                                .before = p.before,
                                .kind = REGISTER_OP_MOVE,
                                .value_id = interval->value_id,
                                .reg = interval->reg,
                                .src_reg = interval->deferred_move_from,
                                .spill = SPILL_NONE}));
  interval->deferred_move_from = REG_NONE;
}

static void emit_deferred_register_ops_if_needed(regalloc2_state *s,
                                                 ls_interval *interval) {
  emit_deferred_reload_if_needed(s, interval);
  emit_deferred_move_if_needed(s, interval);
}

static inline bool reg_matches_interval_class(ls_interval const *interval,
                                              uint8_t reg) {
  if (interval->is_float) {
    return reg >= FPR_REG_START && reg < FPR_REG_END;
  }
  return reg < FPR_REG_START;
}

static void compute_free_until_positions(regalloc2_state *s,
                                         ls_interval const *current,
                                         uint16_t free_until_pos[MAX_REG]) {
  for (int r = 0; r < MAX_REG; r++) {
    free_until_pos[r] =
        reg_matches_interval_class(current, (uint8_t)r) ? UINT16_MAX : 0;
  }

  arr_for_each(s->active_intervals, it) {
    if (it.reg != REG_NONE) {
      free_until_pos[it.reg] = 0;
    }
  }

  for (int r = 0; r < MAX_REG; r++) {
    if (arrlen(s->active_fixed[r]) > 0) {
      free_until_pos[r] = 0;
    }
  }

  for (int r = 0; r < MAX_REG; r++) {
    arr_for_each(s->inactive_fixed[r], range) {
      if (range.start >= current->start && range.start < free_until_pos[r]) {
        free_until_pos[r] = range.start;
      }
    }
  }
}

typedef struct {
  regalloc2_state *s;
  uint16_t pos;
} dense_loc_ctx;

static void collect_dense_loc_from_arg(slot v, void *ctx) {
  if (v.constant) {
    return;
  }
  auto c = (dense_loc_ctx *)ctx;
  arrput(c->s->dense_locs, lookup_loc(c->s, v.loc, c->pos));
}

static void finalize_register_locations(regalloc2_state *s) {
  size_t ins_len = arrlen(s->t->ins);
  if (ins_len == 0) {
    return;
  }

  s->ir_id_to_dense_map = calloc(ins_len, sizeof(uint16_t));
  assert(s->ir_id_to_dense_map != NULL);

  for (uint16_t ir_idx = 0; ir_idx < ins_len; ir_idx++) {
    auto ins = &s->t->ins[ir_idx];
    uint16_t def_pos = ir_after_pos(ir_idx);
    for (size_t i = 0; i < arrlen(s->expired_intervals); i++) {
      auto it = s->expired_intervals[i];
      if (it.value_id == ir_idx && it.start == def_pos) {
        s->t->ins[ir_idx].reg = it.reg;
        break;
      }
    }

    assert(arrlen(s->dense_locs) <= UINT16_MAX);
    s->ir_id_to_dense_map[ir_idx] = (uint16_t)arrlen(s->dense_locs);
    auto ctx = (dense_loc_ctx){.s = s, .pos = ir_before_pos(ir_idx)};
    walk_ir_args(ins, collect_dense_loc_from_arg, &ctx);

    // RET with constant still needs an input register in existing emit path.
    if (ins->op == IR_RET && ins->op1.constant) {
      arrput(s->dense_locs, lookup_loc(s, ir_idx, ir_before_pos(ir_idx)));
    }
  }
}

static void linear_scan_allocate(regalloc2_state *s) {
  while (arrlen(s->unhandled_intervals)) {
    // Find next interval to handle
    auto current = pop_smallest_unhandled_interval(s);

    // Update active/inactive
    expire_active_intervals(s, current.start);
    adjust_active_fixed_intervals(s, current.start);
    adjust_inactive_fixed_intervals(s, current.start);

    // Calculate free until invervals
    uint16_t free_until_pos[MAX_REG];
    compute_free_until_positions(s, &current, free_until_pos);

    uint8_t full_reg = REG_NONE;
    uint16_t full_reg_free_until = 0;
    bool have_full_reg = false;
    uint8_t partial_reg = REG_NONE;
    uint16_t partial_reg_free_until = 0;
    bool hint_full = false;
    bool hint_partial = false;
    for (int r = 0; r < MAX_REG; r++) {
      if (!reg_matches_interval_class(&current, (uint8_t)r)) {
        continue;
      }
      // TODO PMOV hints need to take even if partial.
      uint16_t free_until = free_until_pos[r];
      bool is_hint = current.hint != REG_NONE && (uint8_t)r == current.hint;
      if (is_hint && free_until > current.end) {
        hint_full = true;
      }
      if (is_hint && free_until > current.start) {
        hint_partial = true;
      }
      if (free_until > current.end &&
          (!have_full_reg || free_until < full_reg_free_until)) {
        full_reg = (uint8_t)r;
        full_reg_free_until = free_until;
        have_full_reg = true;
      }
      if (free_until > partial_reg_free_until) {
        partial_reg = (uint8_t)r;
        partial_reg_free_until = free_until;
      }
    }

    // See if we found a valid register.
    uint8_t chosen_reg = REG_NONE;
    if (full_reg != REG_NONE) {
      if (hint_full) {
        chosen_reg = current.hint;
      } else {
        chosen_reg = full_reg;
      }
    } else if (hint_partial) {
      chosen_reg = current.hint;
      split_interval(s, &current, free_until_pos[current.hint], chosen_reg);
    } else if (partial_reg != REG_NONE &&
               partial_reg_free_until > current.start) {
      chosen_reg = partial_reg;
      split_interval(s, &current, partial_reg_free_until, chosen_reg);
    }

    if (chosen_reg != REG_NONE) {
      current.reg = chosen_reg;
      emit_deferred_register_ops_if_needed(s, &current);
      if (current.start == ir_after_pos(current.value_id)) {
        s->t->ins[current.value_id].reg = current.reg;
      }
      arrput(s->active_intervals, current);
      continue;
    }

    // Spilling
    uint16_t next_use_pos[MAX_REG];
    bool reg_ok[MAX_REG] = {0};
    bool owner_was_spilled[MAX_REG] = {0};
    for (int r = 0; r < MAX_REG; r++) {
      if (reg_matches_interval_class(&current, (uint8_t)r)) {
        reg_ok[r] = true;
        next_use_pos[r] = UINT16_MAX;
      } else {
        next_use_pos[r] = 0;
      }
    }

    for (int r = 0; r < MAX_REG; r++) {
      if (!reg_ok[r]) {
        continue;
      }
      if (arrlen(s->active_fixed[r]) > 0) {
        reg_ok[r] = false;
        continue;
      }
      uint16_t fixed_start =
          next_inactive_fixed_start(s, (uint8_t)r, current.start);
      if (fixed_start < next_use_pos[r]) {
        next_use_pos[r] = fixed_start;
      }
    }

    arr_for_each(s->active_intervals, it) {
      if (it.reg == REG_NONE || !reg_ok[it.reg]) {
        continue;
      }
      uint16_t next_use = interval_next_use_from(s, it.value_id, current.start);
      if (next_use <= current.start) {
        reg_ok[it.reg] = false;
        continue;
      }
      if (next_use < next_use_pos[it.reg]) {
        next_use_pos[it.reg] = next_use;
      }
      owner_was_spilled[it.reg] = s->t->ins[it.value_id].spill != SPILL_NONE;
    }

    // We have info, now pick best
    uint8_t spill_reg = REG_NONE;
    uint16_t best_next_use = 0;
    bool best_owner_spilled = false;
    for (int r = 0; r < MAX_REG; r++) {
      if (!reg_ok[r]) {
        continue;
      }
      uint16_t n = next_use_pos[r];
      bool spilled_before = owner_was_spilled[r];
      if (spill_reg == REG_NONE || n > best_next_use ||
          (n == best_next_use && spilled_before && !best_owner_spilled)) {
        spill_reg = (uint8_t)r;
        best_next_use = n;
        best_owner_spilled = spilled_before;
      }
    }
    if (spill_reg == REG_NONE) {
      abort();
    }

    int victim_idx = find_active_interval_by_reg(s, spill_reg);
    // Just for debug checking....
    uint16_t fixed_limit =
        next_inactive_fixed_start(s, spill_reg, current.start);
    if (fixed_limit <= current.start) {
      abort();
    }

    // Spill/split current register owner if there is one.
    if (victim_idx >= 0) {
      auto victim = s->active_intervals[victim_idx];
      assert(victim.start <= current.start);
      assert(victim.end >= current.start);
      spill_active_interval(s, victim, current.start);
      s->active_intervals[victim_idx].end = current.start - 1;
    }

    current.reg = spill_reg;
    emit_deferred_register_ops_if_needed(s, &current);
    if (current.start == ir_after_pos(current.value_id)) {
      s->t->ins[current.value_id].reg = current.reg;
    }
    if (fixed_limit > current.end) {
      arrput(s->active_intervals, current);
    } else {
      split_interval(s, &current, fixed_limit, current.reg);
      arrput(s->active_intervals, current);
    }
  }

  expire_active_intervals(s, UINT16_MAX);
  finalize_register_locations(s);
}

static int register_op_cmp(void const *a, void const *b) {
  auto lhs = (register_op const *)a;
  auto rhs = (register_op const *)b;
  if (lhs->ir_idx < rhs->ir_idx) {
    return -1;
  }
  if (lhs->ir_idx > rhs->ir_idx) {
    return 1;
  }
  if (lhs->before && !rhs->before) {
    return -1;
  }
  if (!lhs->before && rhs->before) {
    return 1;
  }
  if (lhs->kind < rhs->kind) {
    return -1;
  }
  if (lhs->kind > rhs->kind) {
    return 1;
  }
  return 0;
}

regalloc2_result regalloc2(trace *t) {
  regalloc2_state s = {.t = t};
  collect_next_uses(&s);
  if (verbose || getenv("REGALLOC_DEBUG_NEXT_USES")) {
    print_next_uses(&s);
  }

  // PMOVs may be spilled, find them.
  size_t ins_len = arrlen(t->ins);
  s.next_spill = 0;
  for (uint16_t i = 0; i < ins_len; i++) {
    if (t->ins[i].spill != SPILL_NONE &&
        (uint16_t)t->ins[i].spill >= s.next_spill) {
      s.next_spill = (uint8_t)(t->ins[i].spill + 1);
    }
  }

  init_fixed_intervals(&s);
  build_intervals(&s);
  linear_scan_allocate(&s);
  if (arrlen(s.ops) > 1) {
    qsort(s.ops, arrlen(s.ops), sizeof(s.ops[0]), register_op_cmp);
  }

  regalloc2_result out = {};
  out.dense_locs = s.dense_locs;
  out.ir_id_to_dense_map = s.ir_id_to_dense_map;
  out.register_ops = s.ops;

  arrfree(s.unhandled_intervals);
  arrfree(s.active_intervals);
  arrfree(s.expired_intervals);
  arrfree(s.ranges);
  for (int i = 0; i < MAX_REG; i++) {
    arrfree(s.inactive_fixed[i]);
    arrfree(s.active_fixed[i]);
  }
  arrfree(s.next_uses);
  free(s.uses);
  return out;
}

void regalloc2_result_free(regalloc2_result *r) {
  arrfree(r->dense_locs);
  arrfree(r->register_ops);
  free(r->ir_id_to_dense_map);
  memset(r, 0, sizeof(*r));
}
