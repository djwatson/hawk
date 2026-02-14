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
  fixed_range *active_fixed[MAX_REG];
  fixed_range *inactive_fixed[MAX_REG];
  value_range *ranges;
  register_op *ops;
  uint8_t next_spill;
} regalloc2_state;

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

static inline uint16_t ir_before_pos(uint16_t ir_idx) { return ir_idx * 2; }
static inline uint16_t ir_after_pos(uint16_t ir_idx) { return ir_idx * 2 + 1; }

static inline uint16_t pos_ir(uint16_t pos) { return pos / 2; }
static inline bool pos_before(uint16_t pos) { return (pos % 2) == 0; }

static inline uint16_t use_pos(next_use n) {
  return n.before ? ir_before_pos(n.ir_idx) : ir_after_pos(n.ir_idx);
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
                          .hint = REG_NONE};
  arrput(s->unhandled_intervals, it);
  return (int)arrlen(s->unhandled_intervals) - 1;
}

static void build_intervals(regalloc2_state *s) {
  size_t ins_len = arrlen(s->t->ins);
  for (uint16_t v = 0; v < ins_len; v++) {
    auto ins = &s->t->ins[v];
    // RETS need a tmp register (even if no use).
    if (ins->op == IR_RET) {
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
  arrput(s->unhandled_intervals, child);

  interval->end = split_pos - 1;

  uint8_t spill = get_or_assign_spill_slot(s, child.value_id);
  arrput(s->ops, ((register_op){.ir_idx = pos_ir(split_pos),
                                .before = pos_before(split_pos),
                                .kind = REGISTER_OP_MOVE,
                                .value_id = child.value_id,
                                .reg = REG_NONE,
                                .src_reg = parent_reg,
                                .spill = spill}));
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

static void linear_scan_allocate(regalloc2_state *s) {
  int reg_owner[MAX_REG];
  for (int i = 0; i < MAX_REG; i++) {
    reg_owner[i] = -1;
  }

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
    uint16_t full_reg_free_until = UINT16_MAX;
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
      if (free_until > current.end && free_until < full_reg_free_until) {
        full_reg = (uint8_t)r;
        full_reg_free_until = free_until;
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
      s->t->ins[current.value_id].reg = current.reg;
      reg_owner[current.reg] = current.value_id;
      arrput(s->active_intervals, current);
      continue;
    }

    // Spilling section
  }
}
}

regalloc2_result regalloc2(trace *t) {
  regalloc2_state s = {.t = t};
  collect_next_uses(&s);
  if (verbose) {
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

  regalloc2_result out = {};
  out.register_ops = s.ops;

  arrfree(s.unhandled_intervals);
  arrfree(s.active_intervals);
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
