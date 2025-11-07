#include <capstone/capstone.h> // for cs_insn, cs_close, cs_disasm, cs_free

#include "emit.h"

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "array.h"
#include "asm.h"
#include "disassemble.h"
#include "ir.h"
#include "jitdump.h"
#include "record.h"
#include "zone_alloc.h"

typedef struct {
  uint16_t s;
  bool used;
} regmap;
static void assign_snap_registers(size_t snap_num, regmap *regs, trace *t,
                                  uint32_t *next_spill) {
  // Get a free register, if any.  If already assigned a slot, do nothing.
  // If no free registers, assign a slot.
  auto snap = &t->snaps[snap_num];
  arr_for_each_idx(snap->slots, i) {
    auto s = &snap->slots[i];
    if (s->val.constant) {
      continue;
    }
    auto op = &t->ins[s->val.loc];
    if (op->reg != REG_NONE || op->spill != SPILL_NONE) {
      continue;
    }
    // Try and find a free reg, or assign the next spill slot.
    bool done = false;
    for (int j = 0; j < MAX_REG; j++) {
      if (!regs[j].used) {
        op->reg = j;
        regs[op->reg].s = s->val.loc;
        regs[op->reg].used = true;
        done = true;
        // lru_poke(&reg_lru, op->reg);
        /* printf("Assigning snap register %s to op %i\n",
         * reg_names[op->reg], s->val); */
        break;
      }
    }
    if (!done) {
      // Couldn't find a free reg, assign a slot.
      op->spill = (*next_spill)++;
      /* printf("Assigning snap slot %i to op %i\n", op->slot, s->val); */
      assert(*next_spill < 255);
      // check_spill_cnt(*next_spill);
    }
  }
}
// Get a specific reg, spilling if necessary.
static void get_reg(uint8_t reg, trace *trace, uint32_t *next_spill,
                    regmap *slot) {
  if (slot[reg].used) {
    /* // printf("Spilling reg %s\n", reg_names[reg]); */
    /* auto op = slot[reg]; */
    /* assert(trace->ops[op].reg != REG_NONE); */

    /* auto spill = trace->ops[op].slot; */
    /* if (trace->ops[op].slot == SLOT_NONE) { */
    /*   spill = (*next_spill)++; */
    /*   check_spill_cnt(*next_spill); */
    /* } */

    /* trace->ops[op].slot = spill; */
    /* emit_mem_reg(OP_MOV_MR, 0, RTMP, trace->ops[op].reg); */
    /* emit_mov64(RTMP, (int64_t)&spill_slot[trace->ops[op].slot]); */
    /* trace->ops[op].reg = REG_NONE; */
    /* slot[reg] = -1; */
    /* lru_poke(&reg_lru, reg); */
    abort();
  }
  slot[reg].used = true;
}
static int get_free_reg(trace *trace, uint32_t *next_spill, regmap *slot,
                        bool callee) {
  for (int i = 0; i < MAX_REG; i++) {
    if (!slot[i].used) {
      return i;
    }
  }

  abort();
  // Spill.

  // get_reg(oldest, trace, next_spill, slot);
  // return oldest;
}
static void maybe_assign_register(slot v, trace *trace, regmap *slot,
                                  uint32_t *next_spill) {
  if (!v.constant) {
    auto op = &trace->ins[v.loc];
    if (op->reg == REG_NONE) {
      op->reg = get_free_reg(trace, next_spill, slot, false);
      slot[op->reg].s = v.loc;
      slot[op->reg].used = true;
    }
    // TODO
    // lru_poke(&reg_lru, op->reg);
  }
}

static inline ir_ins *slot_ins(trace *t, slot v) {
  assert(!v.constant);
  return &t->ins[v.loc];
}

static inline uint8_t slot_reg(trace *t, slot v) { return slot_ins(t, v)->reg; }

static inline int64_t slot_const(trace *t, slot v) {
  assert(v.constant);
  return t->consts[v.loc].value;
}

static void emit_cmp_slots(emit_state *s, enum cmp_kind cmp, trace *t,
                           regmap *regs, uint32_t *next_spill, slot lhs,
                           slot rhs) {
  assert(!lhs.constant && "LHS must be a register");
  maybe_assign_register(lhs, t, regs, next_spill);
  maybe_assign_register(rhs, t, regs, next_spill);

  if (rhs.constant) {
    emit_cmp_constant(s, cmp, slot_reg(t, lhs), slot_const(t, rhs));
    return;
  }

  emit_cmp(s, cmp, slot_reg(t, lhs), slot_reg(t, rhs));
}

static void emit_arith_slots(emit_state *s, trace *t, regmap *regs,
                             uint32_t *next_spill, uint8_t dst, slot lhs,
                             slot rhs, bool is_sub) {
  assert(!lhs.constant && "Left operand must be in a register");
  maybe_assign_register(lhs, t, regs, next_spill);
  maybe_assign_register(rhs, t, regs, next_spill);

  if (rhs.constant) {
    if (is_sub) {
      emit_sub_constant(s, dst, slot_reg(t, lhs), slot_const(t, rhs));
    } else {
      emit_add_constant(s, dst, slot_reg(t, lhs), slot_const(t, rhs));
    }
  } else {
    if (is_sub) {
      emit_sub(s, dst, slot_reg(t, lhs), slot_reg(t, rhs));
    } else {
      emit_add(s, dst, slot_reg(t, lhs), slot_reg(t, rhs));
    }
  }
}

static char *zone_vsprintf(zone *z, char const *fmt, va_list args) {
  va_list measure;
  va_copy(measure, args);
  int needed = vsnprintf(nullptr, 0, fmt, measure);
  va_end(measure);
  if (needed < 0) {
    abort();
  }

  size_t bytes = (size_t)needed + 1;
  char *buf = zone_malloc(z, bytes);
  if (!buf) {
    abort();
  }

  va_list write_args;
  va_copy(write_args, args);
  int written = vsnprintf(buf, bytes, fmt, write_args);
  va_end(write_args);
  if (written < 0 || written >= (int)bytes) {
    abort();
  }
  return buf;
}

static void comment_append(int64_t offset, zone *z, comment_entry **comments,
                           char const *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  char *msg = zone_vsprintf(z, fmt, args);
  va_end(args);
  comment_entry entry = {.offset = offset, .text = msg};
  arrput(z, *comments, entry);
}

static void emit_stack_offset_and_check(emit_state *s, snap const *snap) {
  if (snap->offset) {
    emit_add_constant(s, RSTACK, RSTACK, snap->offset * 8);

    // TODO
    // check frame overflow
    /* jit_ldxi(s->jit, JIT_R0, JIT_V0, 16); */
    /* auto ok = jit_bltr(s->jit, JIT_R1, JIT_R0); */

    /* // Slow path: Save stack pointer in vm_state, call slowpath, restore
     * stack */
    /* // pointer. */
    /* jit_stxi(s->jit, 8, JIT_V0, JIT_R1); */
    /* jit_calli_1(s->jit, expand_stack, */
    /*             jit_operand_gpr(JIT_OPERAND_ABI_POINTER, JIT_V0)); */
    /* jit_ldxi(s->jit, JIT_R1, JIT_V0, 8); */

    /* jit_patch_here(s->jit, ok); */
  }
}

static void emit_snap_store_entry(emit_state *s, trace *t,
                                  snap_entry const *entry) {
  auto stack_offset = (int64_t)entry->slot * 8;
  if (entry->val.constant) {
    emit_store_constant(s, stack_offset, RSTACK, slot_const(t, entry->val));
    return;
  }

  auto ins = slot_ins(t, entry->val);
  if (ins->type == FLONUM_TAG) {
    abort();
  }

  if (ins->spill != SPILL_NONE) {
    abort();
    /* jit_ldi(s->jit, JIT_R0, */
    /*         &spill_gpr_slots[trace->ir[entry->val.loc].spill]); */
  }

  emit_store(s, stack_offset, RSTACK, ins->reg);
}

static void emit_snap(emit_state *s, trace *t, snap *snap, regmap *regs,
                      bool exit) {
  // If this is an exiting snapshot (vs. a loop back)
  // then record exit PC & snapshot.
  if (exit) {
    emit_mov64(s, RET_REG2, (intptr_t)snap);
    emit_mov(s, RET_REG, RSTACK);
  }

  emit_stack_offset_and_check(s, snap);

  arr_for_each_idx(snap->slots, j) {
    emit_snap_store_entry(s, t, &snap->slots[j]);
  }
}

#define COMMENT(...) comment_append(emit_offset(s), &z, &comments, __VA_ARGS__)

trace_fn emit(trace *t, emit_state *s, record_state *record) {
  // TODO move init somewhere else
  emit_init(s);
  jit_dump_init();

  emit_writable_begin(s);
  regmap reg_to_slot[MAX_REG];
  memset(reg_to_slot, 0, sizeof(reg_to_slot));
  zone z = {};
  comment_entry *comments = nullptr;

  bool reserved[MAX_REG] = {0};
  asm_mark_unallocatable(reserved);
  for (int i = 0; i < MAX_REG; i++) {
    reg_to_slot[i].used = reserved[i];
  }

  long *snap_labels = malloc(sizeof(long) * arrlen(t->snaps));
  auto end = emit_offset(s);
  emit_ret(s);
  restore_callee_regs(s);
  emit_check(s);
  auto exit_label = emit_offset(s);
  for (uint64_t i = arrlen(t->snaps) - 1; i > 0; i--) {
    snap *snap = &t->snaps[i - 1];
    // To be replaced by actual snap exit code at the end.
    emit_jmp32(s, (int32_t)(exit_label - emit_offset(s)));
    snap_labels[i - 1] = emit_offset(s);
    COMMENT("Snap exit #%i", i - 1);
  }

  size_t cur_snap = arrlen(t->snaps) - 1;
  auto op_cnt_idx = arrlen(t->ins);
  uint32_t next_spill = 0;
  assign_snap_registers(cur_snap, reg_to_slot, t, &next_spill);
  if (t->link == t->num) {
    emit_jmp32(s, (int32_t)(exit_label - emit_offset(s)));
    snap_labels[cur_snap] = emit_offset(s);

    emit_snap(s, t, &t->snaps[cur_snap], reg_to_slot, true);
    COMMENT("Loopback (snap exit %i)", cur_snap);
  } else {
    trace *linked_trace = record->traces[t->link];
    emit_jmp32(s, (int32_t)(linked_trace->trace_start - emit_offset(s)));
    emit_snap(s, t, &t->snaps[cur_snap], reg_to_slot, false);
    COMMENT("Link to trace %i (snap exit %i)", t->link, cur_snap);
  }
  bool done = false;
  for (; op_cnt_idx > 0 && !done; op_cnt_idx--) {
    uint16_t op_cnt = op_cnt_idx - 1;
    while (cur_snap >= 0 && t->snaps[cur_snap].ir > op_cnt) {
      if (cur_snap > 0) {
        assign_snap_registers(cur_snap - 1, reg_to_slot, t, &next_spill);
      }
      cur_snap--;
    }
    auto op = &t->ins[op_cnt];

    // Check for spill
    if (op->spill != SPILL_NONE) {
      if (op->reg == REG_NONE) {
        maybe_assign_register((slot){.constant = false, .loc = op_cnt}, t,
                              reg_to_slot, &next_spill);
      }
      // printf("Spilling op %li to slot %i from reg %s\n", op_cnt, op->slot,
      // reg_names[op->reg]);
      abort();
      /* emit_mem_reg(OP_MOV_RM, 0, RTMP, op->reg); */
      /* emit_mov64(RTMP, (int64_t)&spill_slot[op->slot]); */
    }
    /* if (op->reg == REG_NONE) { */
    /*   printf("WARNING: emitting op with no reg: %i\n", op_cnt); */
    /* } */

    // Assign reg to this if it doesn't have a reg yet.
    if (op->op == IR_RET) {
      maybe_assign_register((slot){.constant = false, .loc = op_cnt}, t,
                            reg_to_slot, &next_spill);
    }
    // free current register.
    if (op->reg != REG_NONE && op->reg != RSTACK && op->op != IR_ARG) {
      assert(reg_to_slot[op->reg].s == op_cnt);
      reg_to_slot[op->reg].used = false;
    }

    emit_check(s);
    switch (op->op) {
    case IR_GUARD_EQ: {
      emit_jcc32(s, JNE, snap_labels[cur_snap]);
      emit_cmp_slots(s, CMP_EQ, t, reg_to_slot, &next_spill, op->op1, op->op2);
      break;
    }
    case IR_LOAD: {
      maybe_assign_register(op->op1, t, reg_to_slot, &next_spill);
      assert(!op->op1.constant);
      emit_mem_load(s, (uint16_t)op->op2.loc + 8, slot_reg(t, op->op1),
                    op->reg);
      break;
    }
    case IR_LT: {
      auto lt_fin = emit_offset(s);
      emit_mov64(s, op->reg, TRUE_REP.value);
      auto tr = emit_offset(s);
      // whacky why does jmp32 take absolute, and jcc32 take relative?
      // TODO make this set instead?
      emit_jmp32(s, lt_fin - emit_offset(s));
      emit_mov64(s, op->reg, FALSE_REP.value);
      emit_jcc32(s, JL, tr);
      emit_cmp_slots(s, CMP_LT, t, reg_to_slot, &next_spill, op->op1, op->op2);
      break;
    }
    case IR_SUB: {
      emit_arith_slots(s, t, reg_to_slot, &next_spill, op->reg, op->op1,
                       op->op2, true);
      break;
    }
    case IR_ADD: {
      emit_arith_slots(s, t, reg_to_slot, &next_spill, op->reg, op->op1,
                       op->op2, false);
      break;
    }
    case IR_SLOAD: {
      emit_mem_load(s, op->data * 8, RSTACK, op->reg);
      break;
    }
    case IR_GGET: {
      emit_mem_load(s, 16, RTMP, op->reg);
      emit_mov64(s, RTMP, slot_const(t, op->op1) - SYMBOL_TAG);
      break;
    }
    case IR_RET: {
      // mov ra to a register

      emit_sub_constant(s, RSTACK, RSTACK, slot_const(t, op->op1));
      emit_jcc32(s, JNE, snap_labels[cur_snap]);
      emit_cmp_constant(s, CMP_EQ, op->reg, slot_const(t, op->op2));
      // cmp stack[-1], jmp to snap if not equal
      emit_mem_load(s, -8, RSTACK, op->reg);

      break;
    }
    default: {
      printf("Can't jit op: %s\n", ir_names[op->op]);
      // exit(-1);
    }
    }
    COMMENT("%i %s", op_cnt, ir_names[op->op]);
  }
  // emit parcopy from loop end
  // parcopy from parent trace?
  if (t->link == t->num) { // self link
    emit_jmp32_patch_here(s, snap_labels[arrlen(t->snaps) - 1]);
  }

  t->trace_start = emit_offset(s);
  emit_mov(s, RSTACK, RARG0);
  save_callee_regs(s);
  COMMENT("ENTRY");
  auto entry = emit_offset(s);

  // Emit even MORE snap exits.  We didn't have register allocation previously,
  // but now we do. Since these are slowpath exists, the extra branches probably
  // don't matter much.
  for (uint64_t i = arrlen(t->snaps) - 1; i > 0; i--) {
    snap *snap = &t->snaps[i - 1];
    emit_jmp32(s, (int32_t)(exit_label - emit_offset(s)));
    emit_snap(s, t, snap, reg_to_slot, true);
    emit_jmp32_patch_here(s, snap_labels[i - 1]);
    COMMENT("Snap exit #%i", i - 1);
  }

  emit_writable_end(s);
  auto sz = end - emit_offset(s);
  printf("Disassembly: %" PRId64 "\n", sz);
  arr_reverse(comments);
  disassemble((uint8_t *)emit_offset(s), sz, comments);
  zone_free(&z);
  free(snap_labels);
  jit_reader_add(end - entry, entry);
  jit_dump(sz, emit_offset(s), "TRACE");
  perf_map(emit_offset(s), sz, "TRACE");
  return (trace_fn)entry;
  // emit and done
  // patch if side trace
}
