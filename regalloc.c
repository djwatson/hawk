#include "regalloc.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "asm.h"
#include "hawk.h"
#include "ir.h"

// Reverse linear scan register allocation.  Since it's (mostly) a linear trace,
// it's quite simple.

// For spilling, we just heuristically spill the least used slot.

// For snapshots, if ANY ir in a snapshot was EVER spilled, we must use the
// spill slot (since there are no joins, and the register was reused).

typedef struct {
  uint16_t s;
  bool used;
  uint16_t last_use;
} regmap;

typedef struct {
  uint16_t ir_idx;
  bool before;
  bool is_snap;
  uint32_t next;
} next_use;

typedef struct regalloc_state {
  regmap regs[MAX_REG];
  uint32_t next_spill;
  trace *t;
  reload_info *reloads;
  uint32_t *uses;
  next_use *next_uses;
} regalloc_state;

typedef struct regalloc2_state regalloc2_state;

static inline bool ins_uses_freg(ir_ins const *ins) {
  return ins->type == FLONUM_TAG;
}

static inline ir_ins *slot_ins(trace *t, slot v) {
  assert(!v.constant);
  return &t->ins[v.loc];
}

static uint8_t assign_spill(regalloc_state *s);
static void collect_next_uses(regalloc_state *s);
static void print_next_uses(regalloc_state *s);
static dense_loc_entry lookup_loc(regalloc2_state *s, uint16_t value_id,
                                  uint16_t pos);

static void add_next_use(regalloc_state *s, uint16_t loc, uint16_t ir_idx,
                         bool before, bool is_snap) {
  auto next = (next_use){.ir_idx = ir_idx,
                         .before = before,
                         .is_snap = is_snap,
                         .next = s->uses[loc]};
  s->uses[loc] = (uint32_t)arrlen(s->next_uses);
  arrput(s->next_uses, next);
}

static void collect_next_uses(regalloc_state *s) {
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

static void print_next_uses(regalloc_state *s) {
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
  uint16_t active_start;
  bool active;
  bool done;
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
  fixed_range *fixed[MAX_REG];
  ls_interval *intervals;
  value_range *ranges;
  spill_reload_op *ops;
  uint8_t *spill_slots;
  uint8_t next_spill;
} regalloc2_state;

static inline uint16_t ir_before_pos(uint16_t ir_idx) { return ir_idx * 2; }
static inline uint16_t ir_after_pos(uint16_t ir_idx) { return ir_idx * 2 + 1; }

static inline uint16_t pos_ir(uint16_t pos) { return pos / 2; }
static inline bool pos_before(uint16_t pos) { return (pos % 2) == 0; }

static inline uint16_t snap_capture_pos(snap const *s) {
  return s->ir == 0 ? 0 : ir_after_pos((uint16_t)(s->ir - 1));
}

static inline uint16_t use_pos(next_use n) {
  return n.before ? ir_before_pos(n.ir_idx) : ir_after_pos(n.ir_idx);
}

static uint16_t interval_next_use_pos(regalloc2_state *s, uint16_t value_id,
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

static uint16_t interval_next_ir_use_pos(regalloc2_state *s, uint16_t value_id,
                                         uint16_t from_pos) {
  uint32_t use_idx = s->uses[value_id];
  while (use_idx != 0) {
    auto n = s->next_uses[use_idx];
    if (n.is_snap) {
      use_idx = n.next;
      continue;
    }
    uint16_t pos = use_pos(n);
    if (pos >= from_pos) {
      return pos;
    }
    use_idx = n.next;
  }
  return UINT16_MAX;
}

static bool fixed_covers(regalloc2_state *s, uint8_t reg, uint16_t pos) {
  arr_for_each_idx(s->fixed[reg], i) {
    auto r = s->fixed[reg][i];
    if (r.start <= pos && pos <= r.end) {
      return true;
    }
  }
  return false;
}

static uint16_t fixed_next_start(regalloc2_state *s, uint8_t reg,
                                 uint16_t pos) {
  uint16_t ret = UINT16_MAX;
  arr_for_each_idx(s->fixed[reg], i) {
    auto r = s->fixed[reg][i];
    if (r.start >= pos && r.start < ret) {
      ret = r.start;
    }
  }
  return ret;
}

static void add_fixed_full(regalloc2_state *s, uint8_t reg, uint16_t max_pos) {
  arrput(s->fixed[reg], ((fixed_range){.start = 0, .end = max_pos}));
}

static void add_event(regalloc2_state *s, uint16_t pos, bool is_reload,
                      uint16_t value_id, uint8_t reg, uint8_t spill) {
  auto e = (spill_reload_op){.ir_idx = pos_ir(pos),
                             .before = pos_before(pos),
                             .is_reload = is_reload,
                             .value_id = value_id,
                             .reg = reg,
                             .spill = spill};
  arrput(s->ops, e);
}

static int spill_reload_op_cmp(void const *a, void const *b) {
  auto ea = (spill_reload_op const *)a;
  auto eb = (spill_reload_op const *)b;
  if (ea->ir_idx != eb->ir_idx) {
    return ea->ir_idx < eb->ir_idx ? -1 : 1;
  }
  if (ea->before != eb->before) {
    return ea->before ? -1 : 1;
  }
  if (ea->is_reload != eb->is_reload) {
    // At a use position, spill old reg content before reloading new value.
    return ea->is_reload ? 1 : -1;
  }
  if (ea->reg != eb->reg) {
    return ea->reg < eb->reg ? -1 : 1;
  }
  if (ea->value_id != eb->value_id) {
    return ea->value_id < eb->value_id ? -1 : 1;
  }
  if (ea->spill != eb->spill) {
    return ea->spill < eb->spill ? -1 : 1;
  }
  return 0;
}

static bool ir_uses_value_before(trace const *t, uint16_t ir_idx,
                                 uint16_t value_id) {
  auto ins = &t->ins[ir_idx];
  switch (ir_ins_types[ins->op]) {
  case IR_ARG_IR_IR:
    return (!ins->op1.constant && ins->op1.loc == value_id) ||
           (!ins->op2.constant && ins->op2.loc == value_id);
  case IR_ARG_IR_NONE:
  case IR_ARG_IR_ADDR:
    return !ins->op1.constant && ins->op1.loc == value_id;
  default:
    return false;
  }
}

static void normalize_spill_reload_ops(regalloc2_state *s) {
  arr_for_each_idx(s->ops, i) {
    auto *e = &s->ops[i];
    if (!e->is_reload || !e->before) {
      continue;
    }
    if (!ir_uses_value_before(s->t, e->ir_idx, e->value_id)) {
      continue;
    }
    auto loc = lookup_loc(s, e->value_id, ir_before_pos(e->ir_idx));
    if (loc.kind == LOC_REG) {
      e->reg = loc.reg;
    }
  }

  if (arrlen(s->ops) > 1) {
    qsort(s->ops, arrlen(s->ops), sizeof(spill_reload_op), spill_reload_op_cmp);
  }

  size_t out = 0;
  arr_for_each_idx(s->ops, i) {
    if (out != 0) {
      auto prev = s->ops[out - 1];
      auto cur = s->ops[i];
      if (prev.ir_idx == cur.ir_idx && prev.before == cur.before &&
          prev.is_reload == cur.is_reload && prev.value_id == cur.value_id &&
          prev.reg == cur.reg && prev.spill == cur.spill) {
        continue;
      }
    }
    s->ops[out++] = s->ops[i];
  }
  arrlen_set(s->ops, out);
}

static uint8_t get_or_assign_spill_slot(regalloc2_state *s, uint16_t value_id) {
  if (s->spill_slots[value_id] != SPILL_NONE) {
    return s->spill_slots[value_id];
  }
  assert(s->next_spill < 255);
  s->spill_slots[value_id] = s->next_spill++;
  return s->spill_slots[value_id];
}

static void add_range_reg(regalloc2_state *s, uint16_t value_id, uint16_t start,
                          uint16_t end, uint8_t reg) {
  if (start > end) {
    return;
  }
  arrput(s->ranges, ((value_range){.value_id = value_id,
                                   .start = start,
                                   .end = end,
                                   .in_reg = true,
                                   .loc = reg}));
}

static void add_range_spill(regalloc2_state *s, uint16_t value_id,
                            uint16_t start, uint16_t end, uint8_t spill) {
  if (start > end) {
    return;
  }
  arrput(s->ranges, ((value_range){.value_id = value_id,
                                   .start = start,
                                   .end = end,
                                   .in_reg = false,
                                   .loc = spill}));
}

static int add_interval(regalloc2_state *s, uint16_t value_id, uint16_t start,
                        uint16_t end) {
  auto it = (ls_interval){.value_id = value_id,
                          .start = start,
                          .end = end,
                          .is_float = ins_uses_freg(&s->t->ins[value_id]),
                          .reg = REG_NONE,
                          .active_start = 0,
                          .active = false,
                          .done = false};
  arrput(s->intervals, it);
  return (int)arrlen(s->intervals) - 1;
}

static int pick_next_unhandled(ls_interval *ints) {
  int best = -1;
  for (size_t i = 0; i < arrlen(ints); i++) {
    if (ints[i].done || ints[i].active) {
      continue;
    }
    if (best == -1 || ints[i].start < ints[best].start ||
        (ints[i].start == ints[best].start &&
         ints[i].value_id < ints[best].value_id)) {
      best = (int)i;
    }
  }
  return best;
}

static dense_loc_entry lookup_loc(regalloc2_state *s, uint16_t value_id,
                                  uint16_t pos) {
  arr_for_each_idx(s->ranges, i) {
    auto r = s->ranges[i];
    if (r.value_id == value_id && r.start <= pos && pos <= r.end) {
      if (r.in_reg) {
        return (dense_loc_entry){.kind = LOC_REG,
                                 .reg = r.loc,
                                 .spill = SPILL_NONE,
                                 .value_id = value_id};
      }
      return (dense_loc_entry){.kind = LOC_SPILL,
                               .reg = REG_NONE,
                               .spill = r.loc,
                               .value_id = value_id};
    }
  }

  auto spill = s->spill_slots[value_id];
  assert(spill != SPILL_NONE);
  return (dense_loc_entry){
      .kind = LOC_SPILL, .reg = REG_NONE, .spill = spill, .value_id = value_id};
}

static void build_intervals(regalloc2_state *s) {
  size_t ins_len = arrlen(s->t->ins);
  for (uint16_t v = 0; v < ins_len; v++) {
    uint16_t first_use = interval_next_use_pos(s, v, 0);
    if (first_use == UINT16_MAX) {
      continue;
    }
    uint16_t start = ir_after_pos(v);
    uint16_t end = start > first_use ? start : first_use;
    uint32_t use_idx = s->uses[v];
    while (use_idx != 0) {
      auto n = s->next_uses[use_idx];
      uint16_t p = use_pos(n);
      if (p > end) {
        end = p;
      }
      use_idx = n.next;
    }
    if (end >= start) {
      add_interval(s, v, start, end);
    }
  }
}

static void init_fixed_intervals(regalloc2_state *s) {
  bool reserved[MAX_REG] = {0};
  asm_mark_unallocatable(reserved);
  reserved[FRTMP] = true;
  uint16_t max_pos =
      arrlen(s->t->ins) == 0 ? 0 : (uint16_t)(arrlen(s->t->ins) * 2 - 1);
  for (int r = 0; r < MAX_REG; r++) {
    if (reserved[r]) {
      add_fixed_full(s, (uint8_t)r, max_pos);
    }
  }
}

static void expire_active(regalloc2_state *s, int *reg_owner, uint16_t pos) {
  arr_for_each_idx(s->intervals, i) {
    auto *it = &s->intervals[i];
    if (!it->active) {
      continue;
    }
    if (it->end < pos) {
      add_range_reg(s, it->value_id, it->active_start, it->end, it->reg);
      reg_owner[it->reg] = -1;
      it->active = false;
      it->done = true;
      it->reg = REG_NONE;
    }
  }
}

static void split_interval(regalloc2_state *s, ls_interval *it,
                           uint16_t child_start) {
  if (child_start > it->end) {
    return;
  }
  uint16_t old_end = it->end;
  it->end = child_start - 1;
  add_interval(s, it->value_id, child_start, old_end);
}

static void dump_value_ranges(regalloc2_state *s, uint16_t value_id) {
  fprintf(stderr, "  ranges for v%u:", value_id);
  bool found = false;
  arr_for_each_idx(s->ranges, i) {
    auto r = s->ranges[i];
    if (r.value_id != value_id) {
      continue;
    }
    found = true;
    if (r.in_reg) {
      fprintf(stderr, " [%" PRIu16 ",%" PRIu16 "]=%s", r.start, r.end,
              reg_names[r.loc]);
    } else {
      fprintf(stderr, " [%" PRIu16 ",%" PRIu16 "]=S%u", r.start, r.end, r.loc);
    }
  }
  if (!found) {
    fprintf(stderr, " <none>");
  }
  fprintf(stderr, "\n");
}

static void dump_value_uses(regalloc2_state *s, uint16_t value_id) {
  fprintf(stderr, "  uses for v%u:", value_id);
  uint32_t use_idx = s->uses[value_id];
  if (use_idx == 0) {
    fprintf(stderr, " <none>\n");
    return;
  }
  while (use_idx != 0) {
    auto n = s->next_uses[use_idx];
    fprintf(stderr, " %s%s@%u", n.is_snap ? "S-" : "I-", n.before ? "B" : "A",
            n.ir_idx);
    use_idx = n.next;
  }
  fprintf(stderr, "\n");
}

static void dump_value_intervals(regalloc2_state *s, uint16_t value_id) {
  fprintf(stderr, "  intervals for v%u:", value_id);
  bool found = false;
  arr_for_each_idx(s->intervals, i) {
    auto it = s->intervals[i];
    if (it.value_id != value_id) {
      continue;
    }
    found = true;
    fprintf(stderr, " [%" PRIu16 ",%" PRIu16 "]", it.start, it.end);
  }
  if (!found) {
    fprintf(stderr, " <none>");
  }
  fprintf(stderr, "\n");
}

static void dump_ir_events(regalloc2_state *s, uint16_t ir_idx) {
  fprintf(stderr, "  events at ir=%u:", ir_idx);
  bool found = false;
  arr_for_each_idx(s->ops, i) {
    auto e = s->ops[i];
    if (e.ir_idx != ir_idx) {
      continue;
    }
    found = true;
    fprintf(stderr, " [%s %s v%u reg=%s spill=%u]",
            e.before ? "before" : "after", e.is_reload ? "reload" : "spill",
            e.value_id, reg_names[e.reg], e.spill);
  }
  if (!found) {
    fprintf(stderr, " <none>");
  }
  fprintf(stderr, "\n");
}

static void maybe_add_reload_at_start(regalloc2_state *s, ls_interval const *it,
                                      uint16_t pos) {
  if (pos == 0) {
    return;
  }
  if (s->spill_slots[it->value_id] == SPILL_NONE) {
    return;
  }
  auto prev = lookup_loc(s, it->value_id, (uint16_t)(pos - 1));
  if (prev.kind == LOC_SPILL) {
    add_event(s, pos, true, it->value_id, it->reg, prev.spill);
  }
}

static void linear_scan_allocate(regalloc2_state *s) {
  int reg_owner[MAX_REG];
  for (int i = 0; i < MAX_REG; i++) {
    reg_owner[i] = -1;
  }

  while (true) {
    int cur_idx = pick_next_unhandled(s->intervals);
    if (cur_idx < 0) {
      break;
    }
    auto *cur = &s->intervals[cur_idx];
    uint16_t cur_pos = cur->start;
    expire_active(s, reg_owner, cur_pos);

    uint8_t class_start = cur->is_float ? FPR_REG_START : 0;
    uint8_t class_end = cur->is_float ? FPR_REG_END : FPR_REG_START;
    uint16_t best_full_until = 0;
    int best_full_reg = -1;
    uint16_t best_partial_until = 0;
    int best_partial_reg = -1;

    for (uint8_t reg = class_start; reg < class_end; reg++) {
      uint16_t free_until = UINT16_MAX;
      if (fixed_covers(s, reg, cur_pos)) {
        free_until = cur_pos;
      } else {
        auto fixed_start = fixed_next_start(s, reg, cur_pos);
        if (fixed_start < free_until) {
          free_until = fixed_start;
        }
        int owner = reg_owner[reg];
        if (owner >= 0) {
          continue;
        }
      }
      if (free_until > cur->end) {
        if (best_full_reg < 0 || free_until > best_full_until) {
          best_full_reg = reg;
          best_full_until = free_until;
        }
      } else if (free_until > cur_pos) {
        if (best_partial_reg < 0 || free_until > best_partial_until) {
          best_partial_reg = reg;
          best_partial_until = free_until;
        }
      }
    }

    if (best_full_reg >= 0 || best_partial_reg >= 0) {
      int reg = best_full_reg >= 0 ? best_full_reg : best_partial_reg;
      uint16_t reg_until =
          best_full_reg >= 0 ? UINT16_MAX : (uint16_t)(best_partial_until - 1);
      cur->reg = (uint8_t)reg;
      cur->active_start = cur_pos;
      cur->active = true;
      reg_owner[reg] = cur_idx;
      maybe_add_reload_at_start(s, cur, cur_pos);

      if (reg_until != UINT16_MAX && reg_until < cur->end) {
        split_interval(s, cur, (uint16_t)(reg_until + 1));
      }
      continue;
    }

    if (!pos_before(cur_pos)) {
      uint8_t spill = get_or_assign_spill_slot(s, cur->value_id);
      uint16_t first_use = interval_next_ir_use_pos(s, cur->value_id, cur_pos);
      if (first_use == UINT16_MAX || first_use > cur->end) {
        add_range_spill(s, cur->value_id, cur->start, cur->end, spill);
        cur->done = true;
        continue;
      }
      uint16_t cur_end = cur->end;
      cur->done = true;
      if (first_use > cur_pos) {
        add_range_spill(s, cur->value_id, cur_pos, (uint16_t)(first_use - 1),
                        spill);
      }
      add_interval(s, cur->value_id, first_use, cur_end);
      continue;
    }

    int victim_idx = -1;
    uint16_t victim_next_use = 0;
    int victim_reg = -1;
    bool victim_already_spilled = false;
    for (uint8_t reg = class_start; reg < class_end; reg++) {
      if (fixed_covers(s, reg, cur_pos)) {
        continue;
      }
      int owner = reg_owner[reg];
      if (owner < 0) {
        continue;
      }
      auto *cand = &s->intervals[owner];
      uint16_t next = interval_next_ir_use_pos(s, cand->value_id, cur_pos);
      if (next == cur_pos) {
        continue;
      }
      bool already_spilled = s->spill_slots[cand->value_id] != SPILL_NONE;
      if (victim_idx < 0 || next > victim_next_use ||
          (next == victim_next_use && already_spilled &&
           !victim_already_spilled)) {
        victim_idx = owner;
        victim_next_use = next;
        victim_reg = reg;
        victim_already_spilled = already_spilled;
      }
    }

    if (victim_idx < 0) {
      fprintf(stderr,
              "regalloc2 bailout: no register available at use position "
              "for value %u at pos %u\n",
              cur->value_id, cur_pos);
      fprintf(stderr, "  class regs: [%u,%u)\n", class_start, class_end);
      for (uint8_t reg = class_start; reg < class_end; reg++) {
        bool fixed = fixed_covers(s, reg, cur_pos);
        int owner = reg_owner[reg];
        fprintf(stderr, "  reg=%s fixed=%d owner=%d", reg_names[reg], fixed,
                owner);
        if (owner >= 0) {
          auto *cand = &s->intervals[owner];
          uint16_t next = interval_next_ir_use_pos(s, cand->value_id, cur_pos);
          fprintf(stderr, " owner_v=%u owner_range=[%u,%u] next_use=%u",
                  cand->value_id, cand->start, cand->end, next);
        }
        fprintf(stderr, "\n");
      }
      dump_value_ranges(s, cur->value_id);
      dump_value_intervals(s, cur->value_id);
      dump_value_uses(s, cur->value_id);
      abort();
    }

    auto *victim = &s->intervals[victim_idx];
    uint16_t victim_value_id = victim->value_id;
    uint16_t victim_end = victim->end;
    uint16_t victim_active_start = victim->active_start;
    uint8_t victim_reg_u8 = victim->reg;
    uint8_t spill = get_or_assign_spill_slot(s, victim_value_id);
    if (victim_active_start < cur_pos) {
      add_range_reg(s, victim_value_id, victim_active_start,
                    (uint16_t)(cur_pos - 1), victim_reg_u8);
    }
    uint16_t stack_end = victim_next_use == UINT16_MAX
                             ? victim_end
                             : (uint16_t)(victim_next_use - 1);
    if (stack_end >= cur_pos) {
      add_range_spill(s, victim_value_id, cur_pos, stack_end, spill);
    }
    add_event(s, cur_pos, false, victim_value_id, victim_reg_u8, spill);
    if (victim_next_use != UINT16_MAX && victim_next_use <= victim_end) {
      add_interval(s, victim_value_id, victim_next_use, victim_end);
      add_event(s, victim_next_use, true, victim_value_id, victim_reg_u8, spill);
    }
    reg_owner[victim_reg] = -1;
    s->intervals[victim_idx].active = false;
    s->intervals[victim_idx].done = true;
    s->intervals[victim_idx].reg = REG_NONE;

    s->intervals[cur_idx].reg = (uint8_t)victim_reg;
    s->intervals[cur_idx].active_start = cur_pos;
    s->intervals[cur_idx].active = true;
    reg_owner[victim_reg] = cur_idx;
    maybe_add_reload_at_start(s, &s->intervals[cur_idx], cur_pos);
  }

  arr_for_each_idx(s->intervals, i) {
    auto *it = &s->intervals[i];
    if (it->active) {
      add_range_reg(s, it->value_id, it->active_start, it->end, it->reg);
      it->active = false;
      it->done = true;
    }
  }
}

static void build_dense_maps(regalloc2_state *s, regalloc2_result *out) {
  size_t ins_len = arrlen(s->t->ins);
  size_t snap_len = arrlen(s->t->snaps);
  out->ir_id_to_dense_map = calloc(ins_len, sizeof(uint16_t));
  out->ir_output_locs = calloc(ins_len, sizeof(ir_output_loc));
  out->snap_id_to_dense_map = calloc(snap_len, sizeof(uint16_t));
  assert(out->ir_id_to_dense_map != NULL || ins_len == 0);
  assert(out->ir_output_locs != NULL || ins_len == 0);
  assert(out->snap_id_to_dense_map != NULL || snap_len == 0);

  for (uint16_t i = 0; i < ins_len; i++) {
    out->ir_id_to_dense_map[i] = (uint16_t)arrlen(out->dense_locs);
    auto ins = &s->t->ins[i];
    uint16_t pos = ir_before_pos(i);
    switch (ir_ins_types[ins->op]) {
    case IR_ARG_IR_IR:
      if (!ins->op1.constant) {
        auto loc = lookup_loc(s, ins->op1.loc, pos);
        if (loc.kind != LOC_REG) {
          fprintf(stderr,
                  "regalloc2 invalid: op1 in spill slot at ir=%u value=%u "
                  "spill=%u\n",
                  i, ins->op1.loc, loc.spill);
          dump_value_ranges(s, ins->op1.loc);
          dump_value_intervals(s, ins->op1.loc);
          dump_value_uses(s, ins->op1.loc);
          dump_ir_events(s, i);
          abort();
        }
        arrput(out->dense_locs, loc);
      }
      if (!ins->op2.constant) {
        auto loc = lookup_loc(s, ins->op2.loc, pos);
        if (loc.kind != LOC_REG) {
          fprintf(stderr,
                  "regalloc2 invalid: op2 in spill slot at ir=%u value=%u "
                  "spill=%u\n",
                  i, ins->op2.loc, loc.spill);
          dump_value_ranges(s, ins->op2.loc);
          dump_value_intervals(s, ins->op2.loc);
          dump_value_uses(s, ins->op2.loc);
          dump_ir_events(s, i);
          abort();
        }
        arrput(out->dense_locs, loc);
      }
      break;
    case IR_ARG_IR_NONE:
    case IR_ARG_IR_ADDR:
      if (!ins->op1.constant) {
        auto loc = lookup_loc(s, ins->op1.loc, pos);
        if (loc.kind != LOC_REG) {
          fprintf(stderr,
                  "regalloc2 invalid: op1 in spill slot at ir=%u value=%u "
                  "spill=%u\n",
                  i, ins->op1.loc, loc.spill);
          dump_value_ranges(s, ins->op1.loc);
          dump_value_intervals(s, ins->op1.loc);
          dump_value_uses(s, ins->op1.loc);
          dump_ir_events(s, i);
          abort();
        }
        arrput(out->dense_locs, loc);
      }
      break;
    default:
      break;
    }
    uint16_t out_pos = ir_after_pos(i);
    bool has_uses = s->uses[i] != 0;
    bool has_spill = s->spill_slots[i] != SPILL_NONE;
    if (has_uses || has_spill) {
      out->ir_output_locs[i].present = true;
      out->ir_output_locs[i].loc = lookup_loc(s, i, out_pos);
      if (has_spill && out->ir_output_locs[i].loc.kind == LOC_REG) {
        add_event(s, out_pos, false, i, out->ir_output_locs[i].loc.reg,
                  s->spill_slots[i]);
      }
    }
  }

  for (uint16_t sidx = 0; sidx < snap_len; sidx++) {
    auto sn = &s->t->snaps[sidx];
    uint16_t pos = snap_capture_pos(sn);
    out->snap_id_to_dense_map[sidx] = (uint16_t)arrlen(out->dense_locs);
    arr_for_each_idx(sn->slots, i) {
      auto v = sn->slots[i].val;
      if (!v.constant) {
        auto spill = s->spill_slots[v.loc];
        if (spill != SPILL_NONE) {
          arrput(out->dense_locs,
                 ((dense_loc_entry){.kind = LOC_SPILL,
                                    .reg = REG_NONE,
                                    .spill = spill,
                                    .value_id = v.loc}));
        } else {
          arrput(out->dense_locs, lookup_loc(s, v.loc, pos));
        }
      }
    }
  }
}

static void build_fixed_output(regalloc2_state *s, regalloc2_result *out) {
  out->fixed_reg_to_range_map = calloc(MAX_REG, sizeof(uint16_t));
  assert(out->fixed_reg_to_range_map != NULL);
  for (uint16_t r = 0; r < MAX_REG; r++) {
    out->fixed_reg_to_range_map[r] = (uint16_t)arrlen(out->fixed_ranges);
    arr_for_each_idx(s->fixed[r], i) {
      auto fr = s->fixed[r][i];
      arrput(out->fixed_ranges, ((fixed_reg_range){
                                    .reg = (uint8_t)r,
                                    .start = fr.start,
                                    .end = fr.end,
                                }));
    }
  }
}

regalloc2_result regalloc2(trace *t) {
  regalloc2_state s = {.t = t};
  regalloc_state use_builder = {.t = t};
  collect_next_uses(&use_builder);
  // print_next_uses(&use_builder);
  s.uses = use_builder.uses;
  s.next_uses = use_builder.next_uses;

  size_t ins_len = arrlen(t->ins);
  s.spill_slots = malloc(ins_len * sizeof(uint8_t));
  assert(s.spill_slots != NULL || ins_len == 0);
  memset(s.spill_slots, SPILL_NONE, ins_len * sizeof(uint8_t));

  init_fixed_intervals(&s);
  build_intervals(&s);
  linear_scan_allocate(&s);

  regalloc2_result out = {0};
  build_fixed_output(&s, &out);
  build_dense_maps(&s, &out);
  normalize_spill_reload_ops(&s);
  out.spill_reload_ops = s.ops;

  arrfree(s.intervals);
  arrfree(s.ranges);
  for (int i = 0; i < MAX_REG; i++) {
    arrfree(s.fixed[i]);
  }
  arrfree(s.next_uses);
  free(s.uses);
  free(s.spill_slots);
  return out;
}

void regalloc2_result_free(regalloc2_result *r) {
  if (!r) {
    return;
  }
  arrfree(r->dense_locs);
  arrfree(r->spill_reload_ops);
  arrfree(r->fixed_ranges);
  free(r->ir_output_locs);
  free(r->ir_id_to_dense_map);
  free(r->snap_id_to_dense_map);
  free(r->fixed_reg_to_range_map);
  memset(r, 0, sizeof(*r));
}

static void print_alloc_loc(dense_loc_entry d) {
  if (d.kind == LOC_REG) {
    printf("%s", reg_names[d.reg]);
  } else {
    printf("S%u", d.spill);
  }
}

static void format_alloc_loc(char *buf, size_t n, dense_loc_entry d) {
  if (d.kind == LOC_REG) {
    snprintf(buf, n, "%s", reg_names[d.reg]);
  } else {
    snprintf(buf, n, "S%u", d.spill);
  }
}

static void print_const_slot(slot s, trace *t) {
  assert(s.constant);
  auto gc = t->consts[s.loc];
  if (is_fixnum(gc)) {
    printf("\e[1;35m%" PRId64 "\e[m", to_fixnum(gc));
  } else if (is_char(gc)) {
    printf("\e[1;35m'%c'\e[m", to_char(gc));
  } else if (is_string(gc)) {
    printf("\e[1;35m\"%s\"\e[m", to_string(gc)->str);
  } else if (is_record(gc)) {
    printf("\e[1;35m#<record>\e[m");
  } else if (is_flonum(gc)) {
    printf("\e[1;35m%f\e[m", to_flonum(gc)->x);
  } else if (is_symbol(gc)) {
    auto name = get_sym_name(to_symbol(gc));
    printf("\e[1;35m%s\e[m", name ? name->str : "<symbol>");
  } else if (gc.value == FALSE_REP.value) {
    printf("\e[1;35m#f\e[m");
  } else if (gc.value == TRUE_REP.value) {
    printf("\e[1;35m#t\e[m");
  } else if (is_closure(gc)) {
    printf("\e[1;31mCLOSURE\e[m");
  } else if (is_vector(gc)) {
    printf("\e[1;31mvector\e[m");
  } else if (is_func(gc)) {
    printf("\e[1;31mFUNC\e[m");
  } else if (gc.value == NIL.value) {
    printf("\e[1;35m()\e[m");
  } else {
    printf("\e[1;31mUNKNOWN %" PRIx64 "\e[m", (uint64_t)gc.value);
  }
}

static void print_input_slot(slot s, trace *t, dense_loc_entry const *in_loc) {
  if (s.constant) {
    print_const_slot(s, t);
    return;
  }
  printf("%04u=", s.loc);
  if (in_loc) {
    print_alloc_loc(*in_loc);
  } else {
    printf("?");
  }
}

void regalloc2_print(trace *t, regalloc2_result const *r) {
  size_t ins_len = arrlen(t->ins);
  size_t snap_len = arrlen(t->snaps);
  printf("regalloc2:\n");
  size_t snap_idx = 0;
  for (size_t ir = 0; ir <= ins_len; ir++) {
    while (snap_idx < snap_len && t->snaps[snap_idx].ir == ir) {
      auto sn = &t->snaps[snap_idx];
      size_t sstart = r->snap_id_to_dense_map[snap_idx];
      size_t send = (snap_idx + 1 < snap_len)
                        ? r->snap_id_to_dense_map[snap_idx + 1]
                        : (r->dense_locs ? arrlen(r->dense_locs) : 0);
      size_t entry_len = arrlen(sn->slots);
      size_t *dense_by_entry = calloc(entry_len, sizeof(size_t));
      assert(dense_by_entry != NULL || entry_len == 0);
      for (size_t i = 0; i < entry_len; i++) {
        dense_by_entry[i] = SIZE_MAX;
      }
      size_t j = sstart;
      arr_for_each_idx(sn->slots, k) {
        auto e = sn->slots[k];
        if (!e.val.constant && j < send) {
          dense_by_entry[k] = j++;
        }
      }

      printf("SNAP[ir=%u", sn->ir);
      for (size_t i = entry_len; i != 0; i--) {
        auto e = sn->slots[i - 1];
        printf(" %u=", e.slot);
        if (e.val.constant) {
          print_const_slot(e.val, t);
        } else if (dense_by_entry[i - 1] != SIZE_MAX) {
          print_alloc_loc(r->dense_locs[dense_by_entry[i - 1]]);
        } else {
          printf("?");
        }
      }
      printf("]\n");
      free(dense_by_entry);
      snap_idx++;
    }
    if (ir == ins_len) {
      break;
    }
    arr_for_each_idx(r->spill_reload_ops, eidx) {
      auto e = r->spill_reload_ops[eidx];
      if (e.ir_idx == ir && e.before) {
        printf("    %s BEFORE ir=%zu ", e.is_reload ? "RELOAD" : "SPILL", ir);
        printf("v%u reg=%s spill=%u\n", e.value_id, reg_names[e.reg], e.spill);
      }
    }
    size_t start = r->ir_id_to_dense_map[ir];
    size_t end =
        (ir + 1 < ins_len)
            ? r->ir_id_to_dense_map[ir + 1]
            : (snap_len > 0 ? r->snap_id_to_dense_map[0]
                            : (r->dense_locs ? arrlen(r->dense_locs) : 0));
    auto ins = &t->ins[ir];
    size_t in_idx = start;

    printf("%04zu ", ir);
    if (r->ir_output_locs[ir].present) {
      char out_loc[32];
      format_alloc_loc(out_loc, sizeof(out_loc), r->ir_output_locs[ir].loc);
      printf("%-7s", out_loc);
    } else {
      printf("%-7s", "");
    }
    printf(" %-8s", ir_names[ins->op]);
    switch (ir_ins_types[ins->op]) {
    case IR_ARG_NONE_NONE:
      break;
    case IR_ARG_STACK:
      printf(" \e[1;33mstack %i\e[m", ins->data);
      break;
    case IR_ARG_IR_NONE:
      printf(" ");
      print_input_slot(
          ins->op1, t,
          ins->op1.constant || in_idx >= end ? NULL : &r->dense_locs[in_idx++]);
      break;
    case IR_ARG_IR_IR:
      printf(" ");
      print_input_slot(
          ins->op1, t,
          ins->op1.constant || in_idx >= end ? NULL : &r->dense_locs[in_idx++]);
      printf(", ");
      print_input_slot(
          ins->op2, t,
          ins->op2.constant || in_idx >= end ? NULL : &r->dense_locs[in_idx++]);
      break;
    case IR_ARG_IR_ADDR:
      printf(" ");
      print_input_slot(
          ins->op1, t,
          ins->op1.constant || in_idx >= end ? NULL : &r->dense_locs[in_idx++]);
      printf(", \e[1;35m#<bc 0x%" PRIx64 ">\e[m",
             (uint64_t)t->consts[ins->op2.loc].value);
      break;
    case IR_ARG_REG:
      printf(" \e[1;33m%i\e[m", ins->data);
      break;
    case IR_ARG_PMOV:
      printf(" %i %s (%s)", ins->prev_reg, ins->prev_guard ? "(GUARD)" : "",
             reg_names[ins->prev_reg]);
      break;
    case IR_ARG_OFFSET:
      printf(" +%i", ins->data);
      break;
    }
    printf("\n");
    arr_for_each_idx(r->spill_reload_ops, eidx) {
      auto e = r->spill_reload_ops[eidx];
      if (e.ir_idx == ir && !e.before) {
        printf("    %s AFTER  ir=%zu ", e.is_reload ? "RELOAD" : "SPILL", ir);
        printf("v%u reg=%s spill=%u\n", e.value_id, reg_names[e.reg], e.spill);
      }
    }
  }
}

static int alloc_gpr(regalloc_state *s) {
  for (int i = 0; i < FPR_REG_START; i++) {
    if (!s->regs[i].used) {
      return i;
    }
  }
  return REG_NONE;
}

static int alloc_fpr(regalloc_state *s) {
  for (int i = FPR_REG_START; i < FPR_REG_END; i++) {
    if (!s->regs[i].used) {
      return i;
    }
  }
  return REG_NONE;
}

static int spill_gpr(regalloc_state *s, uint16_t reload_at) {
  int victim = REG_NONE;
  uint16_t farthest_use = 0;
  for (int i = 0; i < FPR_REG_START; i++) {
    if (!s->regs[i].used) {
      continue;
    }
    if (victim == REG_NONE || s->regs[i].last_use > farthest_use) {
      victim = i;
      farthest_use = s->regs[i].last_use;
    }
  }
  assert(victim != REG_NONE);
  auto ir = &s->t->ins[s->regs[victim].s];
  if (ir->spill == SPILL_NONE) {
    ir->spill = assign_spill(s);
  }
  ir->reg = REG_NONE;
  s->regs[victim].used = false;
  arrput(s->reloads,
         ((reload_info){(uint16_t)victim, reload_at, s->regs[victim].s}));
  return victim;
}

static int spill_fpr(regalloc_state *s, uint16_t reload_at) {
  int victim = REG_NONE;
  uint16_t farthest_use = 0;
  for (int i = FPR_REG_START; i < FPR_REG_END; i++) {
    if (!s->regs[i].used) {
      continue;
    }
    if (victim == REG_NONE || s->regs[i].last_use > farthest_use) {
      victim = i;
      farthest_use = s->regs[i].last_use;
    }
  }
  assert(victim != REG_NONE);
  auto ir = &s->t->ins[s->regs[victim].s];
  if (ir->spill == SPILL_NONE) {
    ir->spill = assign_spill(s);
  }
  ir->reg = REG_NONE;
  s->regs[victim].used = false;
  arrput(s->reloads,
         ((reload_info){(uint16_t)victim, reload_at, s->regs[victim].s}));
  return victim;
}

static uint8_t assign_spill(regalloc_state *s) {
  auto ret = (s->next_spill)++;
  assert(s->next_spill < 255);
  return ret;
}

static inline uint8_t slot_reg(trace *t, slot v) {
  return v.constant ? REG_NONE : slot_ins(t, v)->reg;
}

static void assign_snap_registers(regalloc_state *s, size_t snap_num,
                                  trace *t) {
  // Get a free register, if any.  If already assigned a slot, do nothing.
  // If no free registers, assign a slot.
  auto snap = &t->snaps[snap_num];
  arr_for_each_idx(snap->slots, i) {
    auto sl = &snap->slots[i];
    if (sl->val.constant) {
      continue;
    }
    auto op = &t->ins[sl->val.loc];
    if (op->reg != REG_NONE || op->spill != SPILL_NONE) {
      continue;
    }
    // Try and find a free reg, or assign the next spill slot.
    if (ins_uses_freg(op)) {
      op->reg = (uint8_t)alloc_fpr(s);
    } else {
      op->reg = (uint8_t)alloc_gpr(s);
    }
    if (op->reg == REG_NONE) {
      // Couldn't find a free reg, assign a slot.
      op->spill = assign_spill(s);
    } else {
      s->regs[op->reg].s = sl->val.loc;
      s->regs[op->reg].used = true;
    }
  }
}

static void maybe_assign_register(regalloc_state *s, slot v,
                                  uint16_t reload_at) {
  if (!v.constant) {
    auto op = &s->t->ins[v.loc];
    if (op->reg == REG_NONE) {
      op->reg =
          ins_uses_freg(op) ? (uint8_t)alloc_fpr(s) : (uint8_t)alloc_gpr(s);
      if (op->reg == REG_NONE) {
        op->reg = ins_uses_freg(op) ? (uint8_t)spill_fpr(s, reload_at)
                                    : (uint8_t)spill_gpr(s, reload_at);
      }
      s->regs[op->reg].s = v.loc;
      s->regs[op->reg].used = true;
    }
    s->regs[op->reg].last_use = op - s->t->ins;
  }
}

// TODO: once spilling happens, we need to return op1/op2 and tmp register
// assignments at EACH USE.
regalloc_result regalloc(trace *t) {
  if (verbose) {
    auto r2 = regalloc2(t);
    regalloc2_print(t, &r2);
    regalloc2_result_free(&r2);
  }

  regalloc_state s = {0};
  s.t = t;
  size_t ins_len = arrlen(t->ins);
  reg_binding *bindings = malloc(ins_len * sizeof(reg_binding));
  memset(bindings, 0xff, ins_len * sizeof(reg_binding));
  collect_next_uses(&s);
  if (verbose) {
    print_next_uses(&s);
  }

  // Set up register allocator.
  bool reserved[MAX_REG] = {0};
  asm_mark_unallocatable(reserved);
  for (int i = 0; i < MAX_REG; i++) {
    s.regs[i].used = reserved[i];
    s.regs[i].last_use = reserved[i] ? 0 : -1;
  }
  // TODO move this back to asm backends?
  s.regs[FRTMP].used = true;

  // Assign loopback snap registers.
  int32_t cur_snap = (int32_t)arrlen(t->snaps) - 1;
  assign_snap_registers(&s, cur_snap, t);
  auto op_cnt_idx = arrlen(t->ins);
  for (; op_cnt_idx > 0; op_cnt_idx--) {
    uint16_t op_cnt = op_cnt_idx - 1;
    while (cur_snap >= 0 && t->snaps[cur_snap].ir > op_cnt) {
      if (cur_snap > 0) {
        // Assign snap registers.
        assign_snap_registers(&s, cur_snap - 1, t);
      }
      cur_snap--;
    }
    auto op = &t->ins[op_cnt];

    // If we need to spill or typecheck, ensure we have a tmp reg.
    if (op->reg == REG_NONE && (op->spill != SPILL_NONE || op->guard)) {
      maybe_assign_register(&s, (slot){.constant = false, .loc = op_cnt},
                            op_cnt);
    }

    // free current register.  We don't free IR_ARG since they are all
    // live on entry.
    if (op->reg != REG_NONE && op->op != IR_ARG) {
      assert(s.regs[op->reg].s == op_cnt);
      s.regs[op->reg].used = false;
    }

    switch (op->op) {
    case IR_GUARD_EQ:
    case IR_EQ:
    case IR_NE:
    case IR_LT:
    case IR_GT:
    case IR_LTE:
    case IR_GTE:
    case IR_SUB:
    case IR_ADD:
    case IR_MUL:
    case IR_MOD:
    case IR_LOAD:
    case IR_GSET:
    case IR_ALLOC:
      maybe_assign_register(&s, op->op1, op_cnt);
      maybe_assign_register(&s, op->op2, op_cnt);
      bindings[op_cnt].arg[0].reg = slot_reg(t, op->op1);
      bindings[op_cnt].arg[1].reg = slot_reg(t, op->op2);
      break;
    case IR_TYPECHECK:
      maybe_assign_register(&s, op->op1, op_cnt);
      bindings[op_cnt].arg[0].reg = slot_reg(t, op->op1);
      break;
    case IR_STORE:
      // STORE is always IR_STORE + IR_REF, so treat them together.
      auto ref = slot_ins(t, op->op1);
      uint16_t ref_idx = op->op1.loc;
      assert(ref->op == IR_REF);
      maybe_assign_register(&s, ref->op1, op_cnt);
      maybe_assign_register(&s, ref->op2, op_cnt);
      maybe_assign_register(&s, op->op2, op_cnt);
      bindings[op_cnt].arg[1].reg = slot_reg(t, op->op2);
      bindings[ref_idx].arg[0].reg = slot_reg(t, ref->op1);
      bindings[ref_idx].arg[1].reg = slot_reg(t, ref->op2);
      if (!ref->op2.constant) {
        // Need a tmp reg
        maybe_assign_register(&s, (slot){.constant = false, .loc = op_cnt},
                              op_cnt);
        s.regs[op->reg].used = false;
      }

      break;
    case IR_RET:
      // Ret requires a tmp reg.  Alloc one and immediately free it.
      // TODO: actually since there is NEVER anything after ret, we can choose
      // any reg.
      maybe_assign_register(&s, (slot){.constant = false, .loc = op_cnt},
                            op_cnt);
      s.regs[op->reg].used = false;
      break;
    case IR_REF:
    case IR_SLOAD:
    case IR_GGET:
    case IR_ARG:
    case IR_NOP:
    case IR_PMOV:
      break;
    default:
      abort();
    }
  }

  arr_reverse(s.reloads);
  arrfree(s.next_uses);
  free(s.uses);
  return (regalloc_result){.bindings = bindings, .reloads = s.reloads};
}
