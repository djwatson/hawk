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
const char *const reg_names[X64_MAX_REG] = {[0] = "R0"};
#elif defined(__aarch64__)
const char *const reg_names[AARCH64_MAX_REG] = {[0] = "R0"};
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
    break;
  case IR_ARG_IR_NONE:
    ins.op1 = random_slot(r, max_loc, max_const_loc);
    ins.op2 = (slot){.constant = true, .loc = 0};
    break;
  case IR_ARG_IR_ADDR:
    ins.op1 = random_slot(r, max_loc, max_const_loc);
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

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  fuzz_rng rng = {
      .data = Data,
      .size = Size,
      .idx = 0,
      .state = mix_seed(Data, Size),
  };

  trace t = {0};
  fill_consts(&t);
  uint16_t max_const_loc = (uint16_t)(arrlen(t.consts) - 1);
  for (uint16_t i = 0; i < FUZZ_INS_COUNT; i++) {
    fill_instruction(&rng, &t, i, max_const_loc);
  }
  fill_snapshots(&rng, &t);
  print_ir(&t);

  regalloc2_result r = regalloc2(&t);
  regalloc2_result_free(&r);
  free_trace(&t);
  return 0;
}
