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
#define MAX_SPILL 256

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

static size_t ir_row_end(trace const *t, regalloc2_result const *r,
                         uint16_t ir) {
  size_t ins_len = arrlen(t->ins);
  if (ir + 1 < ins_len) {
    return r->ir_id_to_dense_map[ir + 1];
  }
  if (arrlen(t->snaps) > 0) {
    return r->snap_id_to_dense_map[0];
  }
  return arrlen(r->dense_locs);
}

static size_t snap_row_end(trace const *t, regalloc2_result const *r,
                           uint16_t snap_idx) {
  size_t snap_len = arrlen(t->snaps);
  if (snap_idx + 1 < snap_len) {
    return r->snap_id_to_dense_map[snap_idx + 1];
  }
  return arrlen(r->dense_locs);
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
  size_t op_len = arrlen(r->spill_reload_ops);
  size_t snap_cursor = 0;
  size_t snap_len = arrlen(t->snaps);

  for (uint16_t ir = 0; ir < arrlen(t->ins); ir++) {
    while (op_before < op_len) {
      auto e = r->spill_reload_ops[op_before];
      if (e.ir_idx != ir || !e.before) {
        break;
      }
      if (e.is_reload) {
        if (e.spill >= MAX_SPILL || spills[e.spill] != e.value_id ||
            e.reg >= MAX_REG) {
          abort();
        }
        regs[e.reg] = e.value_id;
      } else {
        if (e.reg >= MAX_REG || regs[e.reg] != e.value_id ||
            e.spill >= MAX_SPILL) {
          abort();
        }
        spills[e.spill] = e.value_id;
        regs[e.reg] = UINT16_MAX;
      }
      op_before++;
    }

    auto ins = &t->ins[ir];
    size_t start = r->ir_id_to_dense_map[ir];
    size_t end = ir_row_end(t, r, ir);
    size_t cur = start;
    switch (ir_ins_types[ins->op]) {
    case IR_ARG_IR_IR:
      if (!ins->op1.constant) {
        if (cur >= end || r->dense_locs[cur].value_id != ins->op1.loc) {
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
        if (cur >= end || r->dense_locs[cur].value_id != ins->op2.loc) {
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
        if (cur >= end || r->dense_locs[cur].value_id != ins->op1.loc) {
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
      break;
    default:
      break;
    }
    if (cur != end) {
      abort();
    }

    auto out = r->ir_output_locs[ir];
    if (out.present) {
      auto d = out.loc;
      if (d.value_id != ir) {
        abort();
      }
      if (d.kind == LOC_REG) {
        if (d.reg >= MAX_REG) {
          abort();
        }
        bool out_is_flo = t->ins[ir].type == FLONUM_TAG;
        bool reg_is_fpr = d.reg >= FPR_REG_START && d.reg < FPR_REG_END;
        if (out_is_flo != reg_is_fpr) {
          abort();
        }
        regs[d.reg] = ir;
      } else {
        if (d.spill >= MAX_SPILL) {
          abort();
        }
        spills[d.spill] = ir;
      }
    }

    op_after = op_before;
    while (op_after < op_len) {
      auto e = r->spill_reload_ops[op_after];
      if (e.ir_idx != ir || e.before) {
        break;
      }
      if (e.is_reload) {
        if (e.spill >= MAX_SPILL || spills[e.spill] != e.value_id ||
            e.reg >= MAX_REG) {
          abort();
        }
        regs[e.reg] = e.value_id;
      } else {
        if (e.reg >= MAX_REG || regs[e.reg] != e.value_id ||
            e.spill >= MAX_SPILL) {
          abort();
        }
        spills[e.spill] = e.value_id;
        bool keep_reg = !e.before && e.ir_idx == e.value_id;
        if (!keep_reg) {
          regs[e.reg] = UINT16_MAX;
        }
      }
      op_after++;
    }
    op_before = op_after;

    while (snap_cursor < snap_len &&
           t->snaps[snap_cursor].ir <= (uint16_t)(ir + 1)) {
      snap_cursor++;
    }
    if (snap_cursor > 0) {
      uint16_t last_snap = (uint16_t)(snap_cursor - 1);
      size_t sstart = r->snap_id_to_dense_map[last_snap];
      size_t send = snap_row_end(t, r, last_snap);
      for (size_t j = sstart; j < send; j++) {
        check_loc_holds(regs, spills, r->dense_locs[j], "snapshot", last_snap,
                        r->dense_locs[j].value_id);
      }
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
  for (uint16_t i = 0; i < FUZZ_INS_COUNT; i++) {
    fill_instruction(&rng, &t, i, max_const_loc);
  }
  fill_snapshots(&rng, &t);
  // print_ir(&t);

  regalloc2_result r = regalloc2(&t);
  // regalloc2_print(&t, &r);
  size_t spill_output_count = 0;
  for (size_t ir = 0; ir < arrlen(t.ins); ir++) {
    if (r.ir_output_locs[ir].present &&
        r.ir_output_locs[ir].loc.kind == LOC_SPILL) {
      spill_output_count++;
    }
  }
  size_t spill_op_count = arrlen(r.spill_reload_ops);
  /* if (spill_output_count > 10 || spill_op_count > 10) { */
  /*   printf("regalloc2 spills: outputs=%zu ops=%zu\n", spill_output_count, */
  /*          spill_op_count); */
  /* } */
  verify_regalloc2(&t, &r);
  regalloc2_result_free(&r);
  free_trace(&t);
  return 0;
}
