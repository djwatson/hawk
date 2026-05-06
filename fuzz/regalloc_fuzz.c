#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "hawk.h"
#include "ir.h"
#include "regalloc.h"

bool verbose = false;
bool profile = false;
bool jit_dump_flag = false;
int64_t max_trace = 0;

void emit_init_slowpath(emit_state *s) { (void)s; }

#define FUZZ_INS_COUNT 100
#define FUZZ_CONST_COUNT 64
#define MAX_SPILL SPILL_NONE

typedef enum : uint8_t {
  LOC_REG,
  LOC_SPILL,
} loc_kind;

typedef struct {
  loc_kind kind;
  uint8_t reg;
  uint16_t spill;
  uint16_t value_id;
} dense_loc_entry;

typedef struct {
  uint16_t ir_idx;
  uint16_t value_id;
  uint8_t reg;
} reload_op;

typedef struct {
  dense_loc_entry *dense_locs;
  uint16_t *ir_id_to_dense_map;
  reload_op *reload_ops;
} regalloc_result;

static regalloc_result regalloc(trace *t) {
  regalloc_state s;
  regalloc_state_init(&s, t);
  dense_loc_entry *dense_locs = nullptr;
  uint16_t *ir_id_to_dense_map = nullptr;
  reload_op *reload_ops = nullptr;
  size_t ins_len = arrlen(t->ins);
  size_t snap_idx = 0;
  size_t snap_len = arrlen(t->snaps);

  if (ins_len > 0) {
    ir_id_to_dense_map = malloc(ins_len * sizeof(*ir_id_to_dense_map));
    if (!ir_id_to_dense_map) {
      abort();
    }
  }

  for (size_t i = 0; i < ins_len; i++) {
    while (snap_idx < snap_len && t->snaps[snap_idx].ir == i) {
      if (snap_idx > 0) {
        regalloc_maybe_free_snapshot(&s, (uint16_t)i, &t->snaps[snap_idx - 1]);
      }
      snap_idx++;
    }

    auto ins = &t->ins[i];
    slot args[3];
    uint8_t arg_count = regalloc_collect_ir_args(t, ins, args);

    ir_id_to_dense_map[i] = (uint16_t)arrlen(dense_locs);
    for (uint8_t arg = 0; arg < arg_count; arg++) {
      uint16_t value_id = args[arg].loc;
      uint8_t reg = regalloc_find_current_reg_for_value(&s, value_id);
      if (reg == REG_NONE) {
        auto in = &t->ins[value_id];
        assert(in->spill != SPILL_NONE);
        reg = regalloc_find_free_reg(&s, in->type == FLONUM_TAG, ins);
        s.regs[reg] = value_id;
        arrput(reload_ops,
               ((reload_op){
                   .ir_idx = (uint16_t)i, .value_id = value_id, .reg = reg}));
      }
      arrput(dense_locs,
             ((dense_loc_entry){
                 .kind = LOC_REG, .reg = reg, .value_id = value_id}));
    }
    for (uint8_t arg = 0; arg < arg_count; arg++) {
      regalloc_maybe_free_reg(&s, (uint16_t)i, args[arg].loc, false);
    }

    regalloc_assign_output(&s, (uint16_t)i, ins);
    if (ins->op == IR_RET) {
      auto tmp = regalloc_find_free_reg(&s, false, ins);
      arrput(dense_locs,
             ((dense_loc_entry){
                 .kind = LOC_REG, .reg = tmp, .value_id = (uint16_t)i}));
    }
  }

  regalloc_state_free(&s);
  return (regalloc_result){
      .dense_locs = dense_locs,
      .ir_id_to_dense_map = ir_id_to_dense_map,
      .reload_ops = reload_ops,
  };
}

static void regalloc_result_free(regalloc_result *r) {
  arrfree(r->dense_locs);
  arrfree(r->reload_ops);
  free(r->ir_id_to_dense_map);
  memset(r, 0, sizeof(*r));
}

static uint32_t mix_seed(const uint8_t *data, size_t size) {
  uint32_t x = (uint32_t)size ^ 0x9e3779b9U;
  for (size_t i = 0; i < size; i++) {
    x ^= (uint32_t)data[i] + 0x9e3779b9U + (x << 6) + (x >> 2);
  }
  return x ? x : 0x1234567U;
}

typedef struct {
  const uint8_t *data;
  size_t size;
  size_t idx;
  uint32_t state;
} fuzz_rng;

static uint32_t rng_next(fuzz_rng *r) {
  uint32_t x = r->state;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  r->state = x;
  uint8_t b = 0;
  if (r->size != 0) {
    b = r->data[r->idx % r->size];
    r->idx++;
  }
  return x ^ b;
}

static uint16_t rng_u16(fuzz_rng *r, uint16_t max_inclusive) {
  if (max_inclusive == 0) {
    return 0;
  }
  return (uint16_t)(rng_next(r) % ((uint32_t)max_inclusive + 1));
}

static bool rng_bool(fuzz_rng *r) { return (rng_next(r) & 1U) != 0; }

static uint8_t random_type_tag(fuzz_rng *r) {
  static const uint8_t tags[] = {
      FIXNUM_TAG, FLONUM_TAG, BOOL_TAG, CONS_TAG,
      VECTOR_TAG, SYMBOL_TAG, FUNC_TAG,
  };
  return tags[rng_next(r) % ARRAY_LEN(tags)];
}

static bool random_non_ref_loc(fuzz_rng *r, trace const *t, uint16_t max_ir_loc,
                               uint16_t *out) {
  uint16_t pool[FUZZ_INS_COUNT];
  uint16_t pool_len = 0;
  for (uint16_t i = 0; i <= max_ir_loc; i++) {
    if (t->ins[i].op == IR_REF) {
      continue;
    }
    pool[pool_len++] = i;
  }
  if (pool_len == 0) {
    return false;
  }
  *out = pool[rng_next(r) % pool_len];
  return true;
}

static slot random_slot_no_ref(fuzz_rng *r, trace const *t, uint16_t max_ir_loc,
                               uint16_t max_const_loc) {
  slot s = {0};
  s.constant = rng_bool(r);
  if (s.constant || arrlen(t->ins) == 0) {
    s.constant = true;
    s.loc = rng_u16(r, max_const_loc);
    return s;
  }
  uint16_t loc = 0;
  if (!random_non_ref_loc(r, t, max_ir_loc, &loc)) {
    s.constant = true;
    s.loc = rng_u16(r, max_const_loc);
    return s;
  }
  s.constant = false;
  s.loc = loc;
  return s;
}

static ir_ins_op random_op(fuzz_rng *r) {
  ir_ins_op op;
  do {
    op = (ir_ins_op)(rng_next(r) % IR_INS_MAX);
  } while (op == IR_PMOV || op == IR_ARG || op == IR_REF);
  return op;
}

static uint8_t random_alloc_reg(fuzz_rng *r, bool is_float,
                                bool used_regs[MAX_REG]) {
  bool reserved[MAX_REG] = {0};
  asm_init_unallocatable_regs(reserved);
  reserved[FRTMP] = true;
  uint8_t pool[MAX_REG];
  uint8_t pool_len = 0;
  uint8_t start = is_float ? FPR_REG_START : 0;
  uint8_t end = is_float ? FPR_REG_END : FPR_REG_START;
  for (uint8_t reg = start; reg < end; reg++) {
    if (reserved[reg] || used_regs[reg]) {
      continue;
    }
    pool[pool_len++] = reg;
  }
  if (pool_len == 0) {
    return REG_NONE;
  }
  return pool[rng_next(r) % pool_len];
}

static uint16_t random_unique_spill(fuzz_rng *r, bool used_spills[10]) {
  uint8_t pool[10];
  uint8_t pool_len = 0;
  for (uint8_t i = 0; i < 10; i++) {
    if (!used_spills[i]) {
      pool[pool_len++] = i;
    }
  }
  if (pool_len == 0) {
    return SPILL_NONE;
  }
  return pool[rng_next(r) % pool_len];
}

static void fill_leading_pmov_instruction(fuzz_rng *r, trace *t,
                                          bool used_regs[MAX_REG],
                                          bool used_spills[10]) {
  ir_ins ins = {0};
  ins.op = IR_PMOV;
  ins.type = random_type_tag(r);
  ins.guard = rng_bool(r);
  ins.prev_guard = rng_bool(r);
  ins.reg = REG_NONE;
  ins.spill = SPILL_NONE;
  ins.prev_reg = REG_NONE;

  // Leading PMOVs model side-trace replay with unique precolored locations.
  bool try_spill = rng_bool(r);
  if (try_spill) {
    uint16_t spill = random_unique_spill(r, used_spills);
    if (spill != SPILL_NONE) {
      ins.spill = spill;
      used_spills[spill] = true;
      arrput(t->ins, ins);
      return;
    }
  }

  uint8_t reg = random_alloc_reg(r, ins.type == FLONUM_TAG, used_regs);
  if (reg == REG_NONE) {
    // Fall back to GPR class to keep PMOVs precolored in a legal register.
    ins.type = UNDEFINED_TAG;
    reg = random_alloc_reg(r, false, used_regs);
    if (reg == REG_NONE) {
      uint16_t spill = random_unique_spill(r, used_spills);
      assert(spill != SPILL_NONE);
      ins.spill = spill;
      used_spills[spill] = true;
      arrput(t->ins, ins);
      return;
    }
  }
  ins.reg = reg;
  ins.prev_reg = reg;
  used_regs[reg] = true;

  arrput(t->ins, ins);
}

static uint16_t fill_instruction(fuzz_rng *r, trace *t, uint16_t max_const_loc,
                                 uint16_t slots_left) {
  uint16_t i = (uint16_t)arrlen(t->ins);
  ir_ins ins = {0};
  ins.op = random_op(r);
  ins.type = random_type_tag(r);
  ins.guard = rng_bool(r);
  ins.reg = REG_NONE;
  ins.spill = SPILL_NONE;

  uint16_t max_loc = i == 0 ? 0 : (uint16_t)(i - 1);

  // Match recorder behavior: IR_STORE consumes an IR_REF in op1.
  if (ins.op == IR_STORE) {
    if (i == 0 || slots_left < 2) {
      ins.op = IR_NOP;
    } else {
      ir_ins ref = {0};
      ref.op = IR_REF;
      ref.type = random_type_tag(r);
      ref.guard = rng_bool(r);
      ref.reg = REG_NONE;
      ref.spill = SPILL_NONE;
      ref.op1 = random_slot_no_ref(r, t, max_loc, max_const_loc);
      ref.op2 = random_slot_no_ref(r, t, max_loc, max_const_loc);
      if (i == 0) {
        ref.op1.constant = true;
        ref.op1.loc = rng_u16(r, max_const_loc);
        ref.op2.constant = true;
        ref.op2.loc = rng_u16(r, max_const_loc);
      }
      arrput(t->ins, ref);

      ir_ins store = {0};
      store.op = IR_STORE;
      store.type = ins.type;
      store.guard = ins.guard;
      store.reg = REG_NONE;
      store.spill = SPILL_NONE;
      store.op1 = (slot){.constant = false, .loc = i};
      store.op2 = random_slot_no_ref(r, t, (uint16_t)(arrlen(t->ins) - 1),
                                     max_const_loc);
      arrput(t->ins, store);
      return 2;
    }
  }

  ir_arg_type kind = ir_ins_types[ins.op];
  switch (kind) {
  case IR_ARG_IR_IR:
    ins.op1 = random_slot_no_ref(r, t, max_loc, max_const_loc);
    ins.op2 = random_slot_no_ref(r, t, max_loc, max_const_loc);
    if (i == 0) {
      ins.op1.constant = true;
      ins.op1.loc = rng_u16(r, max_const_loc);
      ins.op2.constant = true;
      ins.op2.loc = rng_u16(r, max_const_loc);
    }
    break;
  case IR_ARG_IR_NONE:
    ins.op1 = random_slot_no_ref(r, t, max_loc, max_const_loc);
    if (i == 0) {
      ins.op1.constant = true;
      ins.op1.loc = rng_u16(r, max_const_loc);
    }
    ins.op2 = (slot){.constant = true, .loc = 0};
    break;
  case IR_ARG_IR_ADDR:
    ins.op1 = random_slot_no_ref(r, t, max_loc, max_const_loc);
    if (ins.op == IR_RET || i == 0) {
      ins.op1.constant = true;
      ins.op1.loc = rng_u16(r, max_const_loc);
    }
    ins.op2 = (slot){.constant = true, .loc = rng_u16(r, max_const_loc)};
    break;
  case IR_ARG_STACK:
  case IR_ARG_REG:
  case IR_ARG_PMOV:
  case IR_ARG_OFFSET:
  case IR_ARG_NONE_NONE:
    ins.data = rng_next(r);
    break;
  }

  arrput(t->ins, ins);
  return 1;
}

static void fill_snapshots(fuzz_rng *r, trace *t) {
  for (uint16_t ir = 1; ir <= FUZZ_INS_COUNT; ir++) {
    if ((rng_next(r) % 5U) != 0) {
      continue;
    }
    snap sn = {0};
    sn.ir = ir;
    sn.offset = 0;

    uint16_t slot_count = (uint16_t)(rng_next(r) % 7U);
    for (uint16_t s = 0; s < slot_count; s++) {
      snap_entry e = {0};
      e.slot = rng_u16(r, 16);
      e.val.constant = rng_bool(r);
      if (e.val.constant) {
        e.val.loc = rng_u16(r, FUZZ_CONST_COUNT - 1);
      } else {
        uint16_t loc = 0;
        if (!random_non_ref_loc(r, t, (uint16_t)(ir - 1), &loc)) {
          e.val.constant = true;
          e.val.loc = rng_u16(r, FUZZ_CONST_COUNT - 1);
        } else {
          e.val.loc = loc;
        }
      }
      arrput(sn.slots, e);
    }
    arrput(t->snaps, sn);
  }
}

static void fill_consts(trace *t) {
  for (uint16_t i = 0; i < FUZZ_CONST_COUNT; i++) {
    arrput(t->consts, tag_fixnum((int64_t)i));
  }
}

static void free_trace(trace *t) {
  arr_for_each_idx(t->snaps, i) { arrfree(t->snaps[i].slots); }
  arrfree(t->snaps);
  arrfree(t->ins);
  arrfree(t->consts);
}

static void check_loc_holds(uint16_t const regs[MAX_REG],
                            uint16_t const spills[MAX_SPILL], dense_loc_entry d,
                            char const *where, uint16_t ir_or_snap,
                            uint16_t value_id) {
  if (d.kind == LOC_REG) {
    if (d.reg >= MAX_REG || regs[d.reg] != d.value_id) {
      fprintf(stderr,
              "check_loc_holds REG fail @%s idx=%u expect_v=%u got_entry_v=%u "
              "reg=%u reg_content=%u\n",
              where, ir_or_snap, value_id, d.value_id, d.reg,
              d.reg < MAX_REG ? regs[d.reg] : UINT16_MAX);
      fflush(stderr);
      abort();
    }
    return;
  }
  if (d.spill >= MAX_SPILL || spills[d.spill] != d.value_id) {
    fprintf(stderr,
            "check_loc_holds SPILL fail @%s idx=%u expect_v=%u got_entry_v=%u "
            "spill=%u spill_content=%u\n",
            where, ir_or_snap, value_id, d.value_id, d.spill,
            d.spill < MAX_SPILL ? spills[d.spill] : UINT16_MAX);
    fflush(stderr);
    abort();
  }
}

static void verify_dense_arg(trace const *t, regalloc_result const *r,
                             uint16_t const regs[MAX_REG],
                             uint16_t const spills[MAX_SPILL], size_t *cur,
                             uint16_t ir, slot arg, char const *where) {
  if (arg.constant) {
    return;
  }
  if (r->dense_locs[*cur].value_id != arg.loc) {
    fprintf(stderr,
            "regalloc verifier: %s value mismatch @ir=%u expect=%u got=%u\n",
            where, ir, arg.loc, r->dense_locs[*cur].value_id);
    abort();
  }
  if (r->dense_locs[*cur].kind != LOC_REG) {
    fprintf(stderr, "regalloc verifier: %s not in register @ir=%u\n", where,
            ir);
    abort();
  }
  check_loc_holds(regs, spills, r->dense_locs[*cur], where, ir, arg.loc);
  (*cur)++;
}

static void verify_regalloc(trace const *t, regalloc_result const *r) {
  uint16_t regs[MAX_REG];
  uint16_t spills[MAX_SPILL];
  for (size_t i = 0; i < MAX_REG; i++) {
    regs[i] = UINT16_MAX;
  }
  for (size_t i = 0; i < MAX_SPILL; i++) {
    spills[i] = UINT16_MAX;
  }

  size_t reload_cursor = 0;
  size_t reload_len = arrlen(r->reload_ops);
  size_t snap_cursor = 0;
  size_t snap_len = arrlen(t->snaps);

  for (uint16_t ir = 0; ir < arrlen(t->ins); ir++) {
    while (reload_cursor < reload_len) {
      auto e = r->reload_ops[reload_cursor];
      if (e.ir_idx != ir) {
        break;
      }
      if (e.reg >= MAX_REG || e.value_id >= arrlen(t->ins)) {
        abort();
      }
      uint16_t spill = t->ins[e.value_id].spill;
      if (spill >= MAX_SPILL || spills[spill] != e.value_id) {
        abort();
      }
      regs[e.reg] = e.value_id;
      reload_cursor++;
    }

    auto ins = &t->ins[ir];
    size_t cur = r->ir_id_to_dense_map[ir];
    if (ins->op == IR_STORE) {
      if (ins->op1.constant || ins->op1.loc >= arrlen(t->ins)) {
        abort();
      }
      auto ref = &t->ins[ins->op1.loc];
      if (ref->op != IR_REF) {
        abort();
      }
      verify_dense_arg(t, r, regs, spills, &cur, ir, ref->op1, "store-ref-op1");
      verify_dense_arg(t, r, regs, spills, &cur, ir, ref->op2, "store-ref-op2");
      verify_dense_arg(t, r, regs, spills, &cur, ir, ins->op2, "store-val");
      goto verify_cursor_done;
    }

    switch (ir_ins_types[ins->op]) {
    case IR_ARG_IR_IR:
      verify_dense_arg(t, r, regs, spills, &cur, ir, ins->op1, "ir-op1");
      verify_dense_arg(t, r, regs, spills, &cur, ir, ins->op2, "ir-op2");
      break;
    case IR_ARG_IR_NONE:
    case IR_ARG_IR_ADDR:
      if (!ins->op1.constant) {
        verify_dense_arg(t, r, regs, spills, &cur, ir, ins->op1, "ir-op1");
      } else if (ins->op == IR_RET) {
        if (r->dense_locs[cur].kind != LOC_REG) {
          abort();
        }
        cur++;
      }
      break;
    default:
      break;
    }
  verify_cursor_done:
    if (ir + 1 < arrlen(t->ins)) {
      if (cur != r->ir_id_to_dense_map[ir + 1]) {
        abort();
      }
    } else if (cur != arrlen(r->dense_locs)) {
      abort();
    }

    if (t->ins[ir].reg != REG_NONE) {
      uint8_t reg = t->ins[ir].reg;
      if (reg >= MAX_REG) {
        abort();
      }
      bool out_is_flo = t->ins[ir].type == FLONUM_TAG;
      bool reg_is_fpr = reg >= FPR_REG_START && reg < FPR_REG_END;
      if (out_is_flo != reg_is_fpr) {
        abort();
      }
      regs[reg] = ir;
    }
    if (t->ins[ir].spill != SPILL_NONE) {
      uint16_t spill = t->ins[ir].spill;
      if (spill >= MAX_SPILL) {
        abort();
      }
      spills[spill] = ir;
    }

    while (snap_cursor < snap_len &&
           t->snaps[snap_cursor].ir <= (uint16_t)(ir + 1)) {
      uint16_t snap_idx = (uint16_t)snap_cursor;
      auto sn = &t->snaps[snap_idx];
      arr_for_each_idx(sn->slots, k) {
        auto v = sn->slots[k].val;
        if (v.constant) {
          continue;
        }
        auto src = &t->ins[v.loc];
        dense_loc_entry loc = {.value_id = v.loc};
        if (src->spill != SPILL_NONE) {
          loc.kind = LOC_SPILL;
          loc.reg = REG_NONE;
          loc.spill = src->spill;
        } else {
          if (src->reg == REG_NONE) {
            abort();
          }
          loc.kind = LOC_REG;
          loc.reg = src->reg;
          loc.spill = SPILL_NONE;
        }
        check_loc_holds(regs, spills, loc, "snapshot", snap_idx, v.loc);
      }
      snap_cursor++;
    }
  }
  if (reload_cursor != reload_len) {
    abort();
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  fuzz_rng rng = {
      .data = Data,
      .size = Size,
      .idx = 0,
      .state = mix_seed(Data, Size),
  };

  // printf("RUN\n");
  trace t = {0};
  fill_consts(&t);
  uint16_t max_const_loc = (uint16_t)(arrlen(t.consts) - 1);
  uint16_t leading_pmov_count = rng_bool(&rng) ? rng_u16(&rng, 10) : 0;
  if (leading_pmov_count > FUZZ_INS_COUNT) {
    leading_pmov_count = FUZZ_INS_COUNT;
  }
  bool used_regs[MAX_REG] = {0};
  bool used_spills[10] = {0};
  for (uint16_t i = 0; i < FUZZ_INS_COUNT;) {
    if (i < leading_pmov_count) {
      fill_leading_pmov_instruction(&rng, &t, used_regs, used_spills);
      i++;
      continue;
    }
    uint16_t slots_left = (uint16_t)(FUZZ_INS_COUNT - i);
    i += fill_instruction(&rng, &t, max_const_loc, slots_left);
  }
  fill_snapshots(&rng, &t);
  /* print_ir(&t, nullptr); */
  regalloc_result r = regalloc(&t);
  /* print_ir(&t, &r); */
  verify_regalloc(&t, &r);
  regalloc_result_free(&r);
  free_trace(&t);
  return 0;
}
