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

#define ALLOC_NONE UINT16_MAX

typedef struct regalloc2_state {
  trace *t;
  uint32_t *uses;
  next_use *next_uses;

  uint16_t regs[MAX_REG];

  dense_loc_entry *dense_locs;
  uint16_t *ir_id_to_dense_map;
  reload_op *ops;
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

static uint8_t get_or_assign_spill_slot(regalloc2_state *s, uint16_t value_id) {
  auto ins = &s->t->ins[value_id];
  if (ins->spill != SPILL_NONE) {
    return ins->spill;
  }
  assert(s->next_spill < 255);
  ins->spill = s->next_spill++;
  return ins->spill;
}

static uint8_t find_free_reg(regalloc2_state *s, bool flonum) {
  uint16_t start = flonum ? FPR_REG_START : 0;
  uint16_t end = flonum ? FPR_REG_END : FPR_REG_START;
  for (uint16_t i = start; i < end; i++) {
    if (s->regs[i] == ALLOC_NONE) {
      return i;
    }
  }
  print_ir(s->t, nullptr);
  abort();
}
static void allocate_reg(slot sl, void *ctx) {
  if (sl.constant) {
    return;
  }
  auto s = (regalloc2_state *)ctx;
  auto ins = &s->t->ins[sl.loc];
}

static void maybe_free_reg(regalloc2_state *s, uint16_t cur_idx, uint16_t idx) {
  auto next_idx = s->uses[idx];
  while (next_idx) {
    auto cur_use = s->next_uses[next_idx];
    if (cur_use.ir_idx <= cur_idx) {
      next_idx = cur_use.next;
      continue;
    }
    break;
  }
  s->uses[idx] = next_idx;

  auto ins = &s->t->ins[idx];
  if (ins->reg == REG_NONE) {
    return;
  }
  // If there is no next use, and we haven't already freed
  // (i.e. multiple uses at some IR op)
  // Then free the register.
  if (!next_idx && s->regs[ins->reg] == idx) {
    s->regs[ins->reg] = ALLOC_NONE;
  }
}

static void maybe_free_snapshot(regalloc2_state *s, uint16_t cur_idx,
                                snap const *sn) {
  arr_for_each_idx(sn->slots, i) {
    auto val = sn->slots[i].val;
    if (!val.constant) {
      maybe_free_reg(s, cur_idx, val.loc);
    }
  }
}

typedef struct {
  regalloc2_state *s;
  uint16_t cur_idx;
} maybe_free_reg_ctx;

static void maybe_free_reg_cb(slot sl, void *ctx) {
  if (sl.constant) {
    return;
  }
  auto c = (maybe_free_reg_ctx *)ctx;
  regalloc2_state *s = c->s;
  uint16_t value_id = sl.loc;
  auto in = &s->t->ins[value_id];
  assert(in->reg != REG_NONE);
  arrput(s->dense_locs, ((dense_loc_entry){.kind = LOC_REG,
                                           .reg = in->reg,
                                           .spill = SPILL_NONE,
                                           .value_id = value_id}));
  maybe_free_reg(s, c->cur_idx, value_id);
}

regalloc2_result regalloc2(trace *t) {
  regalloc2_state s = {
      .t = t, .ir_id_to_dense_map = malloc(arrlen(t->ins) * sizeof(uint16_t))};
  for (uint16_t i = 0; i < MAX_REG; i++) {
    s.regs[i] = ALLOC_NONE;
  }
  bool unallocatable[MAX_REG] = {0};
  asm_mark_unallocatable(unallocatable);
  for (uint16_t i = 0; i < MAX_REG; i++) {
    if (unallocatable[i]) {
      s.regs[i] = 0;
    }
  }

  collect_next_uses(&s);
  if (verbose || getenv("REGALLOC_DEBUG_NEXT_USES")) {
    print_next_uses(&s);
  }

  // PMOVs may be spilled, find them, and find next valid spill slot.
  size_t ins_len = arrlen(t->ins);
  size_t snap_idx = 0;
  size_t snap_len = arrlen(t->snaps);
  s.next_spill = 0;
  for (size_t i = 0; i < ins_len; i++) {
    if (t->ins[i].spill != SPILL_NONE &&
        (uint16_t)t->ins[i].spill >= s.next_spill) {
      s.next_spill = (uint8_t)(t->ins[i].spill + 1);
    }
  }

  for (size_t i = 0; i < ins_len; i++) {
    while (t->snaps[snap_idx].ir == i) {
      if (snap_idx > 0) {
        maybe_free_snapshot(&s, (uint16_t)i, &t->snaps[snap_idx - 1]);
      }
      snap_idx++;
    }

    auto ins = &t->ins[i];
    if (s.uses[i]) {
      uint8_t res;
      if (ins->op == IR_PMOV) {
        res = ins->prev_reg;
        assert(s.regs[res] == ALLOC_NONE);
      } else {
        res = find_free_reg(&s, ins->type == FLONUM_TAG);
      }
      ins->reg = res;
      s.regs[res] = i;
    }
    maybe_free_reg_ctx free_ctx = {.s = &s, .cur_idx = (uint16_t)i};
    s.ir_id_to_dense_map[i] = arrlen(s.dense_locs);
    walk_ir_args(ins, maybe_free_reg_cb, &free_ctx);
    if (ins->op == IR_RET) {
      auto tmp = find_free_reg(&s, false);
      arrput(s.dense_locs,
             ((dense_loc_entry){.kind = LOC_REG, .reg = tmp, .value_id = i}));
    }
  }

  regalloc2_result out = {
      .reload_ops = s.ops,
      .dense_locs = s.dense_locs,
      .ir_id_to_dense_map = s.ir_id_to_dense_map,
  };
  arrfree(s.next_uses);
  free(s.uses);
  return out;
}

void regalloc2_result_free(regalloc2_result *r) {
  arrfree(r->dense_locs);
  arrfree(r->reload_ops);
  free(r->ir_id_to_dense_map);
  memset(r, 0, sizeof(*r));
}
