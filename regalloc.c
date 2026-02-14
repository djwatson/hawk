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
  uint8_t forced_start_reg;
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

static void add_fixed_range(regalloc2_state *s, uint8_t reg, uint16_t start,
                            uint16_t end) {
  if (start > end) {
    return;
  }
  arrput(s->fixed[reg], ((fixed_range){.start = start, .end = end}));
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
  auto ins = &s->t->ins[value_id];
  if (ins->spill != SPILL_NONE) {
    return ins->spill;
  }
  assert(s->next_spill < 255);
  ins->spill = s->next_spill++;
  return ins->spill;
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
  uint8_t forced_start_reg = REG_NONE;
  if (start == ir_after_pos(value_id)) {
    auto ins = &s->t->ins[value_id];
    if (ins->op == IR_PMOV && ins->spill == SPILL_NONE && ins->reg != REG_NONE) {
      forced_start_reg = ins->reg;
    }
  }
  auto it = (ls_interval){.value_id = value_id,
                          .start = start,
                          .end = end,
                          .is_float = ins_uses_freg(&s->t->ins[value_id]),
                          .reg = REG_NONE,
                          .forced_start_reg = forced_start_reg,
                          .active_start = 0,
                          .active = false,
                          .done = false};
  arrput(s->intervals, it);
  return (int)arrlen(s->intervals) - 1;
}

static int add_temp_interval(regalloc2_state *s, uint16_t value_id,
                             uint16_t start, uint16_t end) {
  auto it = (ls_interval){.value_id = value_id,
                          .start = start,
                          .end = end,
                          .is_float = false,
                          .reg = REG_NONE,
                          .forced_start_reg = REG_NONE,
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

  auto spill = s->t->ins[value_id].spill;
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

static void add_ret_tmp_intervals(regalloc2_state *s) {
  size_t ins_len = arrlen(s->t->ins);
  for (uint16_t i = 0; i < ins_len; i++) {
    auto ins = &s->t->ins[i];
    if (ins->op != IR_RET || !ins->op1.constant) {
      continue;
    }
    uint16_t pos = ir_before_pos(i);
    add_temp_interval(s, i, pos, pos);
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
  if (s->t->ins[it->value_id].spill == SPILL_NONE) {
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

    if (cur->forced_start_reg != REG_NONE) {
      uint8_t forced_reg = cur->forced_start_reg;
      if (forced_reg < class_start || forced_reg >= class_end ||
          fixed_covers(s, forced_reg, cur_pos)) {
        fprintf(stderr,
                "regalloc2 invalid PMOV start reg at value=%u reg=%u pos=%u\n",
                cur->value_id, forced_reg, cur_pos);
        abort();
      }
      if (reg_owner[forced_reg] >= 0) {
        fprintf(stderr,
                "regalloc2 invalid PMOV start reg already owned: value=%u "
                "reg=%u owner=%d pos=%u\n",
                cur->value_id, forced_reg, reg_owner[forced_reg], cur_pos);
        abort();
      }

      cur->reg = forced_reg;
      cur->active_start = cur_pos;
      cur->active = true;
      reg_owner[forced_reg] = cur_idx;
      maybe_add_reload_at_start(s, cur, cur_pos);

      uint16_t fixed_start = fixed_next_start(s, forced_reg, cur_pos);
      if (fixed_start != UINT16_MAX && fixed_start > cur_pos) {
        uint16_t forced_until = (uint16_t)(fixed_start - 1);
        if (forced_until < cur->end) {
          split_interval(s, cur, (uint16_t)(forced_until + 1));
        }
      }
      continue;
    }

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
      bool already_spilled = s->t->ins[cand->value_id].spill != SPILL_NONE;
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
      add_event(s, victim_next_use, true, victim_value_id, victim_reg_u8,
                spill);
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

static void append_ir_input_loc(regalloc2_state *s, regalloc2_result *out,
                                uint16_t ir_idx, uint16_t value_id,
                                uint16_t pos, char const *operand_tag) {
  auto loc = lookup_loc(s, value_id, pos);
  if (loc.kind != LOC_REG) {
    fprintf(stderr,
            "regalloc2 invalid: %s in spill slot at ir=%u value=%u spill=%u\n",
            operand_tag, ir_idx, value_id, loc.spill);
    dump_value_ranges(s, value_id);
    dump_value_intervals(s, value_id);
    dump_value_uses(s, value_id);
    dump_ir_events(s, ir_idx);
    abort();
  }
  arrput(out->dense_locs, loc);
}

static void build_dense_maps(regalloc2_state *s, regalloc2_result *out) {
  size_t ins_len = arrlen(s->t->ins);
  out->ir_id_to_dense_map = calloc(ins_len, sizeof(uint16_t));
  assert(out->ir_id_to_dense_map != NULL || ins_len == 0);

  for (uint16_t i = 0; i < ins_len; i++) {
    out->ir_id_to_dense_map[i] = (uint16_t)arrlen(out->dense_locs);
    auto ins = &s->t->ins[i];
    uint16_t pos = ir_before_pos(i);
    switch (ir_ins_types[ins->op]) {
    case IR_ARG_IR_IR:
      if (!ins->op1.constant) {
        append_ir_input_loc(s, out, i, ins->op1.loc, pos, "op1");
      }
      if (!ins->op2.constant) {
        append_ir_input_loc(s, out, i, ins->op2.loc, pos, "op2");
      }
      break;
    case IR_ARG_IR_NONE:
    case IR_ARG_IR_ADDR:
      if (!ins->op1.constant) {
        append_ir_input_loc(s, out, i, ins->op1.loc, pos, "op1");
      } else if (ins->op == IR_RET) {
        auto loc = lookup_loc(s, i, pos);
        if (loc.kind != LOC_REG) {
          fprintf(stderr,
                  "regalloc2 invalid: RET tmp not in register at ir=%u\n", i);
          dump_value_ranges(s, i);
          dump_value_intervals(s, i);
          dump_value_uses(s, i);
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
    bool has_spill = s->t->ins[i].spill != SPILL_NONE;
    if (has_uses || has_spill) {
      auto out_loc = lookup_loc(s, i, out_pos);
      if (has_spill && out_loc.kind == LOC_REG) {
        add_event(s, out_pos, false, i, out_loc.reg, s->t->ins[i].spill);
      }
    }
  }

}

static void write_back_trace_locations(regalloc2_state *s) {
  size_t ins_len = arrlen(s->t->ins);
  for (uint16_t i = 0; i < ins_len; i++) {
    s->t->ins[i].reg = REG_NONE;
    bool has_uses = s->uses[i] != 0;
    bool has_spill = s->t->ins[i].spill != SPILL_NONE;
    if (has_uses || has_spill) {
      auto out_loc = lookup_loc(s, i, ir_after_pos(i));
      if (out_loc.kind == LOC_REG) {
        s->t->ins[i].reg = out_loc.reg;
      }
    }
  }
}

regalloc2_result regalloc2(trace *t) {
  regalloc2_state s = {.t = t};
  collect_next_uses(&s);
  if (verbose) {
    print_next_uses(&s);
  }

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
  add_ret_tmp_intervals(&s);
  linear_scan_allocate(&s);

  regalloc2_result out = {};
  build_dense_maps(&s, &out);
  write_back_trace_locations(&s);
  normalize_spill_reload_ops(&s);
  out.spill_reload_ops = s.ops;

  arrfree(s.intervals);
  arrfree(s.ranges);
  for (int i = 0; i < MAX_REG; i++) {
    arrfree(s.fixed[i]);
  }
  arrfree(s.next_uses);
  free(s.uses);
  return out;
}

void regalloc2_result_free(regalloc2_result *r) {
  if (!r) {
    return;
  }
  arrfree(r->dense_locs);
  arrfree(r->spill_reload_ops);
  free(r->ir_id_to_dense_map);
  memset(r, 0, sizeof(*r));
}
