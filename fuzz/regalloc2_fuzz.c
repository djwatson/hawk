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

#if defined(__x86_64__)
const char *const reg_names[X64_MAX_REG] = {
#define X(name) #name,
    ASM_X64_REGISTER_LIST(X)
#undef X
#define X(name) #name,
        ASM_X64_FREGISTER_LIST(X)
#undef X
};
#elif defined(__aarch64__)
const char *const reg_names[AARCH64_MAX_REG] = {
#define X(name) #name,
    ASM_AARCH64_REGISTER_LIST(X)
#undef X
#define X(name) #name,
        ASM_AARCH64_FREGISTER_LIST(X)
#undef X
};
#else
#error "Unsupported architecture"
#endif

void asm_mark_unallocatable(bool used[MAX_REG]) {
  memset(used, 0, MAX_REG * sizeof(bool));
  used[RTMP] = true;
  used[RSTACK] = true;
  used[RSTATE] = true;
}

string_s *get_sym_name(symbol *s) {
  (void)s;
  return NULL;
}

#define FUZZ_INS_COUNT 100
#define FUZZ_CONST_COUNT 64
#define MAX_SPILL SPILL_NONE

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

static slot random_slot(fuzz_rng *r, uint16_t max_ir_loc,
                        uint16_t max_const_loc) {
  slot s = {0};
  s.constant = rng_bool(r);
  s.loc = s.constant ? rng_u16(r, max_const_loc) : rng_u16(r, max_ir_loc);
  return s;
}

static ir_ins_op random_op(fuzz_rng *r) {
  static const ir_ins_op ops[] = {
      IR_EQ,   IR_NE,    IR_LT,    IR_GTE,       IR_LTE,      IR_GT,
      IR_NOP,  IR_ADD,   IR_SUB,   IR_MUL,       IR_MOD,      IR_GGET,
      IR_GSET, IR_RET,   IR_SLOAD, IR_TYPECHECK, IR_GUARD_EQ, IR_REF,
      IR_LOAD, IR_STORE, IR_ALLOC, IR_INEXACT,
  };
  return ops[rng_next(r) % ARRAY_LEN(ops)];
}

static uint8_t random_alloc_reg(fuzz_rng *r, bool is_float,
                                bool used_regs[MAX_REG]) {
  bool reserved[MAX_REG] = {0};
  asm_mark_unallocatable(reserved);
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

static uint8_t random_unique_spill(fuzz_rng *r, bool used_spills[10]) {
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
  (void)used_spills;
  ir_ins ins = {0};
  ins.op = IR_PMOV;
  ins.type = random_type_tag(r);
  ins.guard = rng_bool(r);
  ins.prev_guard = rng_bool(r);
  ins.reg = REG_NONE;
  ins.spill = SPILL_NONE;
  ins.prev_reg = REG_NONE;

  // Leading PMOVs model side-trace replay: precolored, unique registers.
  uint8_t reg = random_alloc_reg(r, ins.type == FLONUM_TAG, used_regs);
  if (reg == REG_NONE) {
    // Fall back to GPR class to keep leading PMOVs precolored.
    ins.type = UNDEFINED_TAG;
    reg = random_alloc_reg(r, false, used_regs);
    assert(reg != REG_NONE);
  }
  ins.reg = reg;
  ins.prev_reg = reg;
  used_regs[reg] = true;

  arrput(t->ins, ins);
}

static void fill_instruction(fuzz_rng *r, trace *t, uint16_t i,
                             uint16_t max_const_loc) {
  ir_ins ins = {0};
  ins.op = random_op(r);
  ins.type = random_type_tag(r);
  ins.guard = rng_bool(r);
  ins.reg = REG_NONE;
  ins.spill = SPILL_NONE;

  uint16_t max_loc = i == 0 ? 0 : (uint16_t)(i - 1);
  ir_arg_type kind = ir_ins_types[ins.op];
  switch (kind) {
  case IR_ARG_IR_IR:
    ins.op1 = random_slot(r, max_loc, max_const_loc);
    ins.op2 = random_slot(r, max_loc, max_const_loc);
    if (i == 0) {
      ins.op1.constant = true;
      ins.op1.loc = rng_u16(r, max_const_loc);
      ins.op2.constant = true;
      ins.op2.loc = rng_u16(r, max_const_loc);
    }
    break;
  case IR_ARG_IR_NONE:
    ins.op1 = random_slot(r, max_loc, max_const_loc);
    if (i == 0) {
      ins.op1.constant = true;
      ins.op1.loc = rng_u16(r, max_const_loc);
    }
    ins.op2 = (slot){.constant = true, .loc = 0};
    break;
  case IR_ARG_IR_ADDR:
    ins.op1 = random_slot(r, max_loc, max_const_loc);
    if (i == 0) {
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
        e.val.loc = rng_u16(r, (uint16_t)(ir - 1));
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

static void verify_regalloc2(trace const *t, regalloc2_result const *r) {
  uint16_t regs[MAX_REG];
  uint16_t spills[MAX_SPILL];
  for (size_t i = 0; i < MAX_REG; i++) {
    regs[i] = UINT16_MAX;
  }
  for (size_t i = 0; i < MAX_SPILL; i++) {
    spills[i] = UINT16_MAX;
  }

  size_t op_before = 0;
  size_t op_after = 0;
  size_t op_len = arrlen(r->register_ops);
  size_t snap_cursor = 0;
  size_t snap_len = arrlen(t->snaps);

  for (uint16_t ir = 0; ir < arrlen(t->ins); ir++) {
    while (op_before < op_len) {
      auto e = r->register_ops[op_before];
      if (e.ir_idx != ir || !e.before) {
        break;
      }
      if (e.kind == REGISTER_OP_RELOAD) {
        if (e.spill >= MAX_SPILL || spills[e.spill] != e.value_id ||
            e.reg >= MAX_REG) {
          abort();
        }
        regs[e.reg] = e.value_id;
      } else if (e.kind == REGISTER_OP_MOVE) {
        if (e.src_reg >= MAX_REG || regs[e.src_reg] != e.value_id) {
          fprintf(
              stderr,
              "MOVE before fail ir=%u op_idx=%zu v=%u src_reg=%u src_has=%u "
              "dst_reg=%u spill=%u\n",
              ir, op_before, e.value_id, e.src_reg,
              e.src_reg < MAX_REG ? regs[e.src_reg] : UINT16_MAX, e.reg,
              e.spill);
          abort();
        }
        if (e.reg != REG_NONE) {
          if (e.reg >= MAX_REG) {
            abort();
          }
          regs[e.reg] = e.value_id;
        }
        if (e.spill != SPILL_NONE) {
          if (e.spill >= MAX_SPILL) {
            abort();
          }
          spills[e.spill] = e.value_id;
        }
      } else {
        abort();
      }
      op_before++;
    }

    auto ins = &t->ins[ir];
    size_t cur = r->ir_id_to_dense_map[ir];
    switch (ir_ins_types[ins->op]) {
    case IR_ARG_IR_IR:
      if (!ins->op1.constant) {
        if (r->dense_locs[cur].value_id != ins->op1.loc) {
          abort();
        }
        if (r->dense_locs[cur].kind != LOC_REG) {
          fprintf(stderr, "regalloc2 verifier: ir-op1 not in register @ir=%u\n",
                  ir);
          abort();
        }
        check_loc_holds(regs, spills, r->dense_locs[cur], "ir-op1", ir,
                        ins->op1.loc);
        cur++;
      }
      if (!ins->op2.constant) {
        if (r->dense_locs[cur].value_id != ins->op2.loc) {
          abort();
        }
        if (r->dense_locs[cur].kind != LOC_REG) {
          fprintf(stderr, "regalloc2 verifier: ir-op2 not in register @ir=%u\n",
                  ir);
          abort();
        }
        check_loc_holds(regs, spills, r->dense_locs[cur], "ir-op2", ir,
                        ins->op2.loc);
        cur++;
      }
      break;
    case IR_ARG_IR_NONE:
    case IR_ARG_IR_ADDR:
      if (!ins->op1.constant) {
        if (r->dense_locs[cur].value_id != ins->op1.loc) {
          abort();
        }
        if (r->dense_locs[cur].kind != LOC_REG) {
          fprintf(stderr, "regalloc2 verifier: ir-op1 not in register @ir=%u\n",
                  ir);
          abort();
        }
        check_loc_holds(regs, spills, r->dense_locs[cur], "ir-op1", ir,
                        ins->op1.loc);
        cur++;
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
      uint8_t spill = t->ins[ir].spill;
      if (spill >= MAX_SPILL) {
        abort();
      }
      spills[spill] = ir;
    }

    op_after = op_before;
    while (op_after < op_len) {
      auto e = r->register_ops[op_after];
      if (e.ir_idx != ir || e.before) {
        break;
      }
      if (e.kind == REGISTER_OP_RELOAD) {
        if (e.spill >= MAX_SPILL || spills[e.spill] != e.value_id ||
            e.reg >= MAX_REG) {
          abort();
        }
        regs[e.reg] = e.value_id;
      } else if (e.kind == REGISTER_OP_MOVE) {
        if (e.src_reg >= MAX_REG || regs[e.src_reg] != e.value_id) {
          fprintf(stderr,
                  "MOVE after fail ir=%u op_idx=%zu v=%u src_reg=%u src_has=%u "
                  "dst_reg=%u spill=%u\n",
                  ir, op_after, e.value_id, e.src_reg,
                  e.src_reg < MAX_REG ? regs[e.src_reg] : UINT16_MAX, e.reg,
                  e.spill);
          abort();
        }
        if (e.reg != REG_NONE) {
          if (e.reg >= MAX_REG) {
            abort();
          }
          regs[e.reg] = e.value_id;
        }
        if (e.spill != SPILL_NONE) {
          if (e.spill >= MAX_SPILL) {
            abort();
          }
          spills[e.spill] = e.value_id;
        }
      } else {
        abort();
      }
      op_after++;
    }
    op_before = op_after;

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
  for (uint16_t i = 0; i < FUZZ_INS_COUNT; i++) {
    if (i < leading_pmov_count) {
      fill_leading_pmov_instruction(&rng, &t, used_regs, used_spills);
      continue;
    }
    fill_instruction(&rng, &t, i, max_const_loc);
  }
  fill_snapshots(&rng, &t);
  /* print_ir(&t, nullptr); */
  regalloc2_result r = regalloc2(&t);
  /* print_ir(&t, &r); */
  size_t spill_output_count = 0;
  for (size_t ir = 0; ir < arrlen(t.ins); ir++) {
    if (t.ins[ir].spill != SPILL_NONE && t.ins[ir].reg == REG_NONE) {
      spill_output_count++;
    }
  }
  size_t spill_op_count = arrlen(r.register_ops);
  /* if (spill_output_count > 10 || spill_op_count > 10) { */
  /*   printf("regalloc2 spills: outputs=%zu ops=%zu\n", spill_output_count, */
  /*          spill_op_count); */
  /* } */
  verify_regalloc2(&t, &r);
  regalloc2_result_free(&r);
  free_trace(&t);
  return 0;
}
