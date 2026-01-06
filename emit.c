#include <capstone/capstone.h> // for cs_insn, cs_close, cs_disasm, cs_free

#include "emit.h"

#include <assert.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "array.h"
#include "asm.h"
#include "disassemble.h"
#include "gc.h"
#include "hawk.h"
#include "ir.h"
#include "profiler.h"
#include "vm.h"
#ifdef HAVE_ELF_H
#include "jitdump.h"
#endif
#include "parallel_copy.h"
#include "record.h"
#include "zone_alloc.h"

static_assert((sizeof(flonum_s) & 7) == 0, "flonum_s must be 8-byte aligned");
enum : int32_t {
  FLONUM_SIZE_CLASS = (int32_t)(sizeof(flonum_s) / 8),
};
static_assert(FLONUM_SIZE_CLASS < (int32_t)size_classes,
              "flonum size class must exist");
static freelist_s *const flonum_freelist = &freelist[FLONUM_SIZE_CLASS];
static const int32_t freelist_start_offset =
    (int32_t)offsetof(freelist_s, start_ptr);
static const int32_t freelist_end_offset =
    (int32_t)offsetof(freelist_s, end_ptr);
static const int32_t flonum_payload_offset = (int32_t)offsetof(flonum_s, x);

static void register_jit_symbol(uint8_t *start, uint8_t *entry, uint8_t *end,
                                const char *name) {
  profiler_register_jit_symbol(start, end, name);
#ifdef HAVE_ELF_H
  if (jit_dump_flag) {
    jit_reader_add((int)(end - entry), (uint64_t)entry, name);
    jit_dump((int)(end - start), (uint64_t)start, name);
    perf_map((uint64_t)start, (uint64_t)(end - start), name);
  }
#endif
}

// Slowpath: RET_REG will be the requested size, AND return value.
void emit_init_slowpath(emit_state *s) {
  if (s->alloc_slowpath) {
    return;
  }
  // TODO: we COULD optimize this for preserve_most
  uint8_t slowpath_regs[64];
  size_t reg_cnt = 0;
  for (int i = 0; i < FPR_REG_END; i++) {
    if (i != RET_REG && !asm_is_callee_saved(i) && i != SP) {
      slowpath_regs[reg_cnt++] = i;
    }
  }

  auto end = emit_offset(s);

  emit_writable_begin(s);

  emit_ret(s);
  emit_pop_regs(s, slowpath_regs, reg_cnt, true);

  emit_call_reg(s, RTMP);
  emit_mov64(s, RTMP, (int64_t)&gc_alloc);
  emit_mov(s, RARG0, RET_REG);
  emit_push_regs(s, slowpath_regs, reg_cnt, true);
  auto start = (uint8_t *)emit_offset(s);
  s->alloc_slowpath = start;

  emit_writable_end(s);
  register_jit_symbol(start, s->alloc_slowpath, (uint8_t *)end, "GCslowpath");
  if (verbose) {
    printf("GC slowpath: %" PRId64 "\n", end - (long)start);
    disassemble(start, end - (long)start, nullptr);
  }
}

static inline bool ins_uses_freg(ir_ins const *ins) {
  return ins->type == FLONUM_TAG;
}

static inline bool is_fpr_reg(uint8_t reg) { return reg >= FPR_REG_START; }

static int alloc_gpr(emit_state *s) {
  for (int i = 0; i < FPR_REG_START; i++) {
    if (!s->regs[i].used) {
      return i;
    }
  }
  return REG_NONE;
}

static int alloc_fpr(emit_state *s) {
  for (int i = FPR_REG_START; i < FPR_REG_END; i++) {
    if (!s->regs[i].used) {
      return i;
    }
  }
  return REG_NONE;
}

static void assign_snap_registers(emit_state *s, size_t snap_num, trace *t) {
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
      op->spill = (s->next_spill)++;
      /* printf("Assigning snap slot %i to op %i\n", op->slot, sl->val); */
      assert(s->next_spill < 255);
      // check_spill_cnt(s->next_spill);
    } else {
      s->regs[op->reg].s = sl->val.loc;
      s->regs[op->reg].used = true;
    }
  }
}
// Get a specific reg, spilling if necessary.
/* static void get_reg(emit_state *s, uint8_t reg, trace *trace) { */
/*   if (s->regs[reg].used) { */
/*     /\* // printf("Spilling reg %s\n", reg_names[reg]); *\/ */
/*     /\* auto op = s->regs[reg]; *\/ */
/*     /\* assert(trace->ops[op].reg != REG_NONE); *\/ */

/*     /\* auto spill = trace->ops[op].slot; *\/ */
/*     /\* if (trace->ops[op].slot == SLOT_NONE) { *\/ */
/*     /\*   spill = (s->next_spill)++; *\/ */
/*     /\*   check_spill_cnt(s->next_spill); *\/ */
/*     /\* } *\/ */

/*     /\* trace->ops[op].slot = spill; *\/ */
/*     /\* emit_mem_reg(OP_MOV_MR, 0, RTMP, trace->ops[op].reg); *\/ */
/*     /\* emit_mov64(RTMP, (int64_t)&spill_slot[trace->ops[op].slot]); *\/ */
/*     /\* trace->ops[op].reg = REG_NONE; *\/ */
/*     /\* s->regs[reg] = -1; *\/ */
/*     /\* lru_poke(&reg_lru, reg); *\/ */
/*     abort(); */
/*   } */
/*   s->regs[reg].used = true; */
/* } */
static void maybe_assign_register(emit_state *s, slot v, trace *trace) {
  if (!v.constant) {
    auto op = &trace->ins[v.loc];
    if (op->reg == REG_NONE) {
      op->reg =
          ins_uses_freg(op) ? (uint8_t)alloc_fpr(s) : (uint8_t)alloc_gpr(s);
      if (op->reg == REG_NONE) {
        abort();
      }
      s->regs[op->reg].s = v.loc;
      s->regs[op->reg].used = true;
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

static void emit_cmp_slots(emit_state *s, trace *t, slot lhs, slot rhs) {
  assert(!lhs.constant && "LHS must be a register");
  maybe_assign_register(s, lhs, t);
  maybe_assign_register(s, rhs, t);

  if (rhs.constant) {
    emit_cmp_constant(s, slot_reg(t, lhs), slot_const(t, rhs));
    return;
  }

  emit_cmp(s, slot_reg(t, lhs), slot_reg(t, rhs));
}

static void emit_arith_slots(emit_state *s, trace *t, uint8_t dst, slot lhs,
                             slot rhs, bool is_sub) {
  assert(!lhs.constant && "Left operand must be in a register");
  maybe_assign_register(s, lhs, t);
  maybe_assign_register(s, rhs, t);

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

static void append_global_comment(emit_state *s, int64_t offset,
                                  char const *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  char *msg = zone_vsprintf(&s->global_comment_zone, fmt, args);
  va_end(args);
  comment_entry entry = {.offset = offset, .text = msg};
  arrput(&s->global_comment_zone, s->global_comments, entry);
}

void emit_add_global_comment(emit_state *s, int64_t offset, const char *fmt,
                             ...) {
  va_list args;
  va_start(args, fmt);
  char *msg = zone_vsprintf(&s->global_comment_zone, fmt, args);
  va_end(args);
  comment_entry entry = {.offset = offset, .text = msg};
  arrput(&s->global_comment_zone, s->global_comments, entry);
}

static inline ir_ins *next_leading_op(trace *t, ir_ins_op op, size_t *idx) {
  size_t len = arrlen(t->ins);
  while (*idx < len) {
    ir_ins *ins = &t->ins[(*idx)++];
    if (ins->op == IR_NOP) {
      continue;
    }
    if (ins->op != op) {
      *idx = len;
      return nullptr;
    }
    return ins;
  }
  return nullptr;
}

#define for_each_leading_op(trace_ptr, opcode, ins_var)                        \
  for (size_t _##ins_var##_idx = 0;                                            \
       ((ins_var) =                                                            \
            next_leading_op((trace_ptr), (opcode), &_##ins_var##_idx));)

static __attribute__((preserve_all)) gc_obj *
jit_expand_stack_slowpath(vm_state *state, gc_obj *stack) {
  expand_stack(state, &stack);
  return stack;
}

#define COMMENT(...)                                                           \
  comment_append(emit_offset(s), &s->z, &s->comments, __VA_ARGS__)

typedef struct {
  uint16_t slot;
  uint8_t reg;
  uint8_t target_reg;
  bool needs_constant;
  int64_t constant_value;
  bool needs_stack_load;
  uint8_t type;
} ignoremap;

// NOLINTBEGIN(clang-analyzer-core.NullDereference)
static size_t collect_regs_to_preserve(ignoremap *ignore,
                                       uint8_t regs[MAX_REG]) {
  size_t count = 0;
  bool added[MAX_REG] = {0};
  size_t ignore_len = arrlen(ignore);
  for (size_t i = 0; i < ignore_len; i++) {
    uint8_t reg = ignore[i].reg;
    if (reg == REG_NONE) {
      continue;
    }
    if (reg >= FPR_REG_END) {
      abort();
    }
    if (asm_is_callee_saved(reg)) {
      continue;
    }
    if (added[reg]) {
      continue;
    }
    regs[count++] = reg;
    added[reg] = true;
  }
  return count;
}

static void emit_stack_offset_and_check(emit_state *s, snap const *snap,
                                        ignoremap *ignore) {
  if (!snap->offset) {
    return;
  }

  uint8_t regs_to_save[MAX_REG];
  size_t regs_cnt = collect_regs_to_preserve(ignore, regs_to_save);

  emit_add_constant(s, RSTACK, RSTACK, (int64_t)snap->offset * 8);

  auto done = emit_offset(s);

  emit_pop_regs(s, regs_to_save, regs_cnt, false);
  emit_mov(s, RSTACK, RET_REG);
  emit_call_reg(s, RTMP);

  emit_mov64(s, RTMP, (intptr_t)&jit_expand_stack_slowpath);
  emit_mov(s, RARG0, RSTATE);
  emit_mov(s, RARG1, RSTACK);
  emit_push_regs(s, regs_to_save, regs_cnt, false);

  emit_jcc32(s, JL, done);
  emit_cmp(s, RSTACK, RTMP);
  emit_mem_load(s, (int32_t)offsetof(vm_state, stack_limit), RSTATE, RTMP);
  COMMENT("Emit stack guard check");
}

static double slot_flonum_constant(trace *t, slot v) {
  assert(v.constant);
  gc_obj obj = t->consts[v.loc];
  // assert(is_flonum(obj));
  if (is_flonum(obj)) {
    return to_flonum(obj)->x;
  }
  abort();
}

static void emit_flonum_sub(emit_state *s, trace *t, ir_ins *op) {
  assert(is_fpr_reg(op->reg));
  if (op->op2.constant) {
    emit_fsub_constant(s, op->reg, slot_reg(t, op->op1),
                       slot_flonum_constant(t, op->op2));
    return;
  }
  emit_fsub(s, op->reg, slot_reg(t, op->op1), slot_reg(t, op->op2));
}

static void emit_flonum_cmp(emit_state *s, trace *t, ir_ins *op) {
  if (op->op2.constant) {
    emit_fcmp_constant(s, slot_reg(t, op->op1),
                       slot_flonum_constant(t, op->op2));
    return;
  }
  emit_fcmp(s, slot_reg(t, op->op1), slot_reg(t, op->op2));
}
static void emit_flonum_add(emit_state *s, trace *t, ir_ins *op) {
  assert(is_fpr_reg(op->reg));
  if (op->op2.constant) {
    emit_fadd_constant(s, op->reg, slot_reg(t, op->op1),
                       slot_flonum_constant(t, op->op2));
    return;
  }
  emit_fadd(s, op->reg, slot_reg(t, op->op1), slot_reg(t, op->op2));
}

static void emit_snap_store_flonum(emit_state *s, int32_t stack_offset,
                                   ir_ins *ins) {
  assert(s->alloc_slowpath);
  assert(is_fpr_reg(ins->reg));
  emit_pop(s, RET_REG);
  emit_pop(s, RET_REG2);

  // Do stuff with allocated space.
  emit_store(s, stack_offset, RSTACK, RTMP);
  emit_add_constant(s, RTMP, RTMP, FLONUM_TAG);
  emit_mov(s, RTMP, RET_REG);
  emit_fstore(s, flonum_payload_offset, RET_REG, ins->reg);
  emit_store_constant(s, 0, RET_REG, FLONUM_TAG);

  auto slow_continue_label = emit_offset(s);
  // There WAS space, store new freelist end.
  emit_store(s, freelist_start_offset, RTMP, RET_REG2);
  emit_mov64(s, RTMP, (intptr_t)flonum_freelist);
  emit_mov(s, RET_REG2, RTMP);

  // No space, call slowpath
  auto continue_label = emit_offset(s);
  emit_jmp32(s, slow_continue_label);
  emit_call32(s, (int64_t)s->alloc_slowpath);
  emit_mov64(s, RET_REG, sizeof(flonum_s));

  // Check for fastpath space
  emit_jcc32(s, JLE, continue_label);
  emit_cmp(s, RTMP, RET_REG2);
  emit_add_constant(s, RTMP, RTMP, (int32_t)sizeof(flonum_s));
  emit_mov(s, RTMP, RET_REG);
  emit_mem_load(s, freelist_end_offset, RTMP, RET_REG2);
  emit_mem_load(s, freelist_start_offset, RTMP, RET_REG);
  emit_mov64(s, RTMP, (intptr_t)flonum_freelist);

  emit_push(s, RET_REG2);
  emit_push(s, RET_REG);
}

static void emit_snap_store_entry(emit_state *s, trace *t,
                                  snap_entry const *entry) {
  auto stack_offset = (int32_t)entry->slot * 8;
  if (entry->val.constant) {
    emit_store_constant(s, stack_offset, RSTACK, slot_const(t, entry->val));
    return;
  }

  auto ins = slot_ins(t, entry->val);
  if (ins->type == FLONUM_TAG) {
    emit_snap_store_flonum(s, stack_offset, ins);
    return;
  }

  if (ins->spill != SPILL_NONE) {
    abort();
    /* jit_ldi(s->jit, JIT_R0, */
    /*         &spill_gpr_slots[trace->ir[entry->val.loc].spill]); */
  }

  emit_store(s, stack_offset, RSTACK, ins->reg);
}

// Collect list of ARG registers used in trace and map them to exit values.
static ignoremap *collect_loopback_regs(trace *arg_trace, trace *exit_trace,
                                        snap *sn) {
  ignoremap *regs = nullptr;
  ir_ins *ins = nullptr;
  for_each_leading_op(arg_trace, IR_ARG, ins) {
    if (ins->spill != SPILL_NONE) {
      abort();
    }
    ignoremap map = {.slot = (uint16_t)(sn->offset + ins->data)};
    bool found = false;
    arr_for_each_idx(sn->slots, j) {
      auto entry = &sn->slots[j];
      if (entry->slot != map.slot) {
        continue;
      }
      found = true;
      if (entry->val.constant) {
        map.needs_constant = true;
        map.constant_value = slot_const(exit_trace, entry->val);
      } else {
        map.reg = slot_reg(exit_trace, entry->val);
        map.needs_constant = false;
        map.type = slot_ins(exit_trace, entry->val)->type;
      }
      break;
    }
    if (!found) {
      map.needs_stack_load = true;
      map.reg = REG_NONE;
      map.type = ins->type;
    }
    arrput(nullptr, regs, map);
  }
  return regs;
}
static void emit_loopback_constants(emit_state *s, ignoremap *loopback_regs) {
  if (!loopback_regs) {
    return;
  }
  arr_for_each_idx(loopback_regs, i) {
    auto map = &loopback_regs[i];
    if (!map->needs_constant) {
      continue;
    }
    if (map->target_reg == REG_NONE) {
      abort();
    }
    if (map->target_reg >= FPR_REG_START) {
      emit_fmov_constant(s, map->target_reg,
                         to_flonum((gc_obj){.value = map->constant_value})->x);
    } else {
      emit_mov64(s, map->target_reg, map->constant_value);
    }
  }
}

static const uint8_t PAR_MOVE_MARKER = UINT8_MAX;

static uint8_t resolve_tmp_reg(uint8_t peer) {
  if (peer != PAR_MOVE_MARKER && is_fpr_reg(peer)) {
    return FRTMP;
  }
  return RTMP;
}

static void emit_serialized_moves(emit_state *s, par_copy *cpy,
                                  ignoremap *loopback_regs) {
  emit_loopback_constants(s, loopback_regs);
  par_copy *moves = serialize_parallel_copy(cpy, PAR_MOVE_MARKER);
  arr_reverse(moves);
  arr_for_each_idx(moves, i) {
    auto mov = moves[i];
    uint8_t from = mov.from;
    uint8_t to = mov.to;
    if (from == PAR_MOVE_MARKER) {
      from = resolve_tmp_reg(to);
    }
    if (to == PAR_MOVE_MARKER) {
      to = resolve_tmp_reg(from);
    }
    bool dst_fpr = is_fpr_reg(to);
    bool src_fpr = is_fpr_reg(from);
    if (dst_fpr || src_fpr) {
      assert(dst_fpr && src_fpr);
      emit_fmov(s, to, from);
    } else {
      emit_mov(s, to, from);
    }
  }
  arrfree(cpy);
  arrfree(moves);
}
static void emit_typecheck(emit_state *s, trace *t, ir_ins *op,
                           int32_t cur_snap) {
  assert(op->guard);
  if (op->type == FIXNUM_TAG) {
    emit_jcc32(s, JNE, (int64_t)t->snaps[cur_snap].patch_point);
    emit_test_constant(s, op->reg, TAG_MASK);
    COMMENT("  typecheck");
  } else if (op->type == CONS_TAG) {
    emit_jcc32(s, JNE, (int64_t)t->snaps[cur_snap].patch_point);
    emit_cmp_constant(s, RTMP, CONS_TAG);
    emit_and_constant(s, RTMP, RTMP, TAG_MASK);
    emit_mov(s, RTMP, op->reg);
    COMMENT("  typecheck");
  } else if (op->type == FLONUM_TAG) {
    // These are already typechecked (and are in xmm register).
  } else {
    // TODO TODO TODO
    /* abort(); */
  }
}

// Collect destination of loopback exist register/constant/spill slot values.
// Arrange
static void collect_loopback_parallel_moves(emit_state *s, trace *arg_trace,
                                            ignoremap *loopback_regs) {
  par_copy *cpy = nullptr;
  size_t arg_idx = 0;
  ir_ins *arg_ins = nullptr;
  for_each_leading_op(arg_trace, IR_ARG, arg_ins) {
    if (arg_ins->spill != SPILL_NONE || arg_ins->reg == REG_NONE) {
      abort();
    }
    auto reg_map = &loopback_regs[arg_idx++];
    reg_map->target_reg = arg_ins->reg;
    if (reg_map->needs_constant) {
      continue;
    }
    if (reg_map->needs_stack_load) {
      if (reg_map->type == FLONUM_TAG) {
        auto stack_off = (int32_t)reg_map->slot * 8;
        emit_fmem_load(s, 8 - FLONUM_TAG, RTMP, reg_map->target_reg);
        emit_mem_load(s, stack_off, RSTACK, RTMP);
        emit_mov(s, RTMP, reg_map->target_reg);
      } else {
        auto stack_off = (int32_t)reg_map->slot * 8;
        emit_mem_load(s, stack_off, RSTACK, reg_map->target_reg);
      }
      continue;
    }
    if (reg_map->reg == REG_NONE) {
      abort();
    }
    arrput(nullptr, cpy,
           ((par_copy){.from = reg_map->reg, .to = arg_ins->reg}));
  }
  emit_serialized_moves(s, cpy, loopback_regs);
}

static void emit_snap0_args(emit_state *s, trace *t, snap *snap) {
  ir_ins *arg_ins = nullptr;
  for_each_leading_op(t, IR_ARG, arg_ins) {
    uint16_t arg_slot = (uint16_t)(snap->offset + arg_ins->data);
    snap_entry entry = {
        .slot = arg_slot,
        .val =
            {
                .constant = false,
                .loc = (uint16_t)(arg_ins - t->ins),
            },
    };
    emit_snap_store_entry(s, t, &entry);
  }
}

static void emit_snap(emit_state *s, trace *t, snap *snap, bool exit,
                      ignoremap *ignore) {
  // If this is an exiting snapshot (vs. a loop back)
  // then record exit PC & snapshot.
  if (exit) {
    emit_mov64(s, RET_REG2, (intptr_t)snap);
    emit_mov(s, RET_REG, RSTACK);
  }

  emit_stack_offset_and_check(s, snap, ignore);

  if (snap == &t->snaps[0]) {
    emit_snap0_args(s, t, snap);
  }

  arr_for_each_idx(snap->slots, j) {
    bool ignored = false;
    for (size_t i = 0; i < arrlen(ignore); i++) {
      if (snap->slots[j].slot == ignore[i].slot) {
        ignored = true;
        break;
      }
    }
    if (!ignored) {
      emit_snap_store_entry(s, t, &snap->slots[j]);
    }
  }
}
// NOLINTEND(clang-analyzer-core.NullDereference)

static void emit_exit_to_c(emit_state *s) {
  emit_check(s);
  emit_ret(s);
  restore_callee_regs(s);
}

static void emit_snapshot_exit_jumps(emit_state *s, snap *snaps) {
  for (uint64_t i = arrlen(snaps) - 1; i > 0; i--) {
    snap *snap = &snaps[i - 1];
    // To be replaced by actual snap exit code at the end, so just put a
    // placeholder to reserve instruction space.
    auto unused = emit_offset(s) + 16;
    emit_jmp32(s, unused);
    snap->patch_point = emit_offset(s);
    COMMENT("Snap exit #%i", i - 1);
  }
}

static ignoremap *link_to_next_trace(emit_state *s, trace *t) {
  ignoremap *loopback_regs = nullptr;
  auto cur_snap = arrlen(t->snaps) - 1;
  assign_snap_registers(s, cur_snap, t);
  auto sn = &t->snaps[cur_snap];
  trace *linked_trace = t->link;
  loopback_regs = collect_loopback_regs(linked_trace, t, sn);
  if (t->link == t) {
    // We're linking to ourselves.  Unfortunately we don't have
    // register allocation information yet for the *start* of the
    // trace, only the end.  So save the loopback_regs state, and we
    // will do a parallel move to make them match later

    // To be patched when we've emitted the entry label.
    auto unused = emit_offset(s) + 16;
    emit_jmp32(s, unused);
    sn->patch_point = emit_offset(s);

    emit_snap(s, t, sn, false, loopback_regs);
    COMMENT("Loopback (snap exit %i)", cur_snap);
  } else {
    // Generate a parallel move so our exit state matches the linked
    // trace's entry state.

    // For things we flush to memory this is no big deal, this is more
    // complicated because traces expect the first REG_ARG_CNT args in memory.
    // (the same way most calling conventions keep the first X args in
    // register).
    emit_jmp32(s, (int64_t)linked_trace->trace_start);
    collect_loopback_parallel_moves(s, linked_trace, loopback_regs);
    emit_snap(s, t, sn, false, loopback_regs);
    arrfree(loopback_regs);
    COMMENT("Link to trace %i (snap exit %i)", t->link->num, cur_snap);
  }
  return loopback_regs;
}

static void emit_ir(emit_state *s, trace *t) {
  int32_t cur_snap = (int32_t)arrlen(t->snaps) - 1;
  auto op_cnt_idx = arrlen(t->ins);
  for (; op_cnt_idx > 0; op_cnt_idx--) {
    uint16_t op_cnt = op_cnt_idx - 1;
    while (cur_snap >= 0 && t->snaps[cur_snap].ir > op_cnt) {
      if (cur_snap > 0) {
        assign_snap_registers(s, cur_snap - 1, t);
      }
      cur_snap--;
    }
    auto op = &t->ins[op_cnt];

    // Check for spill
    if (op->spill != SPILL_NONE) {
      if (op->reg == REG_NONE) {
        maybe_assign_register(s, (slot){.constant = false, .loc = op_cnt}, t);
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
      maybe_assign_register(s, (slot){.constant = false, .loc = op_cnt}, t);
    }
    // free current register.
    if (op->reg != REG_NONE && op->op != IR_ARG) {
      if (op->reg != RSTACK) {
        assert(s->regs[op->reg].s == op_cnt);
        s->regs[op->reg].used = false;
      }
    }

    emit_check(s);
    switch (op->op) {
    case IR_GUARD_EQ:
    case IR_EQ: {
      emit_jcc32(s, JNE, (int64_t)t->snaps[cur_snap].patch_point);
      emit_cmp_slots(s, t, op->op1, op->op2);
      break;
    }
    case IR_NE: {
      emit_jcc32(s, JE, (int64_t)t->snaps[cur_snap].patch_point);
      emit_cmp_slots(s, t, op->op1, op->op2);
      break;
    }
    case IR_LOAD: {
      maybe_assign_register(s, op->op1, t);
      assert(!op->op1.constant);
      assert(op->op2.constant);
      if (op->guard) {
        emit_typecheck(s, t, op, cur_snap);
      }
      int64_t offset_bytes =
          to_fixnum(t->consts[op->op2.loc]) + (int64_t)sizeof(gc_header);
      emit_mem_load(s, (int32_t)offset_bytes, slot_reg(t, op->op1), op->reg);
      break;
    }
    case IR_STORE: {
      ir_ins *ref = slot_ins(t, op->op1);
      assert(ref->op == IR_REF);

      if (op->reg == REG_NONE) {
        maybe_assign_register(s, (slot){.constant = false, .loc = op_cnt}, t);
      }

      maybe_assign_register(s, ref->op1, t);
      if (!ref->op2.constant) {
        maybe_assign_register(s, ref->op2, t);
      }
      if (!op->op2.constant) {
        maybe_assign_register(s, op->op2, t);
      }

      uint8_t base_reg = slot_reg(t, ref->op1);

      if (op->op2.constant) {
        emit_store(s, 0, op->reg, RTMP);
        emit_mov64(s, RTMP, slot_const(t, op->op2));
      } else {
        emit_store(s, 0, op->reg, slot_reg(t, op->op2));
      }
      emit_add(s, op->reg, op->reg, base_reg);
      if (ref->op2.constant) {
        int64_t offset = slot_const(t, ref->op2) + (int64_t)(8 - op->type);
        emit_mov64(s, op->reg, offset);
      } else {
        emit_add_constant(s, op->reg, op->reg, 8 - op->type);
        emit_mov(s, op->reg, slot_reg(t, ref->op2));
      }
      if (op->reg != REG_NONE) {
        s->regs[op->reg].used = false;
      }
      break;
    }
    case IR_REF: {
      break;
    }
    case IR_LT: {
      emit_jcc32(s, JGE, (int64_t)t->snaps[cur_snap].patch_point);
      emit_cmp_slots(s, t, op->op1, op->op2);
      break;
    }
    case IR_GT: {
      emit_jcc32(s, JLE, (int64_t)t->snaps[cur_snap].patch_point);
      emit_cmp_slots(s, t, op->op1, op->op2);
      break;
    }
    case IR_GTE: {
      enum jcc_cond guard = (op->type == FLONUM_TAG) ? JB : JL;
      emit_jcc32(s, guard, (int64_t)t->snaps[cur_snap].patch_point);
      if (op->type == FLONUM_TAG) {
        maybe_assign_register(s, op->op1, t);
        maybe_assign_register(s, op->op2, t);
        emit_flonum_cmp(s, t, op);
      } else {
        emit_cmp_slots(s, t, op->op1, op->op2);
      }
      break;
    }
    case IR_SUB: {
      if (op->type == FLONUM_TAG) {
        maybe_assign_register(s, op->op1, t);
        maybe_assign_register(s, op->op2, t);
        emit_flonum_sub(s, t, op);
      } else {
        if (op->guard) {
          emit_typecheck(s, t, op, cur_snap);
        }
        emit_arith_slots(s, t, op->reg, op->op1, op->op2, true);
      }
      break;
    }
    case IR_ADD: {
      if (op->type == FLONUM_TAG) {
        maybe_assign_register(s, op->op1, t);
        maybe_assign_register(s, op->op2, t);
        emit_flonum_add(s, t, op);
      } else {
        emit_arith_slots(s, t, op->reg, op->op1, op->op2, false);
      }
      break;
    }
    case IR_SLOAD: {
      if (op->guard) {
        emit_typecheck(s, t, op, cur_snap);
      }
      if (op->type == FLONUM_TAG) {
        emit_fmem_load(s, 8 - FLONUM_TAG, RTMP, op->reg);
        // We need to typecheck to verify it is a flonum.
        // TODO if we had a spare register this would be more efficent.
        emit_mem_load(s, (int32_t)op->data * 8, RSTACK, RTMP);
        emit_jcc32(s, JNE, (int64_t)t->snaps[0].patch_point);
        emit_cmp_constant(s, RTMP, FLONUM_TAG);
        emit_and_constant(s, RTMP, RTMP, TAG_MASK);
        emit_mem_load(s, (int32_t)op->data * 8, RSTACK, RTMP);
        COMMENT("  flonum typecheck");
      } else {
        emit_mem_load(s, (int32_t)op->data * 8, RSTACK, op->reg);
      }
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
      emit_jcc32(s, JNE, (int64_t)t->snaps[cur_snap].patch_point);
      emit_cmp_constant(s, op->reg, slot_const(t, op->op2));
      // cmp stack[-1], jmp to snap if not equal
      emit_mem_load(s, -8, RSTACK, op->reg);
      /* if (t->num == 1 && op_cnt == 6) { */
      /*   emit_jmp32(s, snap_labels[cur_snap]); */
      /*   COMMENT("ABORT"); */
      /* } */

      break;
    }
    case IR_ALLOC: {
      if (op->reg == REG_NONE) {
        maybe_assign_register(s, (slot){.constant = false, .loc = op_cnt}, t);
      }
      assert(op->reg != REG_NONE);
      assert(op->reg != RET_REG);
      assert(op->op1.constant);
      assert(op->op2.constant);
      int64_t size_bytes = slot_const(t, op->op1) >> FIXNUM_SHIFT;
      assert((size_bytes & 7) == 0);
      uint64_t type_val = (uint64_t)(slot_const(t, op->op2) >> FIXNUM_SHIFT);
      uint8_t tag_bits = (uint8_t)(type_val & TAG_MASK);
      assert(s->alloc_slowpath);

      if (op->reg != RET_REG) {
        emit_pop(s, RET_REG);
        emit_pop(s, RET_REG);
      }
      emit_add_constant(s, op->reg, RET_REG, tag_bits);
      emit_store_constant(s, 0, RET_REG, (int64_t)type_val);
      emit_call32(s, (int64_t)s->alloc_slowpath);
      emit_mov64(s, RET_REG, size_bytes);
      if (op->reg != RET_REG) {
        emit_push(s, RET_REG);
        emit_push(s, RET_REG);
      }
      break;
    }
    case IR_ARG:
    case IR_NOP:
    case IR_PMOV:
      // Typecheck
      if (op->guard) {
        if (op->op == IR_PMOV && op->prev_guard) {
          // No need to guard twice, parent trace already ran guard.
          break;
        }
        emit_typecheck(s, t, op, cur_snap);
      }
      // Done at end.
      break;
    default: {
      printf("Can't jit op: %s\n", ir_names[op->op]);
      abort();
      // exit(-1);
    }
    }
    // TODO: maybe move emit_typecheck here, instead of each individual one.
    if (op->guard &&
        !(op->op == IR_ARG || op->op == IR_PMOV || op->op == IR_SLOAD ||
          op->op == IR_SUB || op->op == IR_LOAD || op->op == IR_ALLOC)) {
      abort();
    }
    COMMENT("%i %s", op_cnt, ir_names[op->op]);
  }
}

// Emit *two* entry points:
// One that loops back from the current trace
// One from c.
static void emit_root_trace_entry(emit_state *s, trace *t,
                                  ignoremap *loopback_regs,
                                  const snap *poly_entry) {
  size_t snap_cnt = arrlen(t->snaps);
  if (!snap_cnt) {
    return;
  }
  // Emit a loopbackentry point
  // emit parcopy from loop end
  collect_loopback_parallel_moves(s, t, loopback_regs);

  if (t->link == t) { // self link
    emit_jmp32_patch_here(s,
                          (int64_t)t->snaps[arrlen(t->snaps) - 1].patch_point);
  }
  COMMENT("LOOPBACK ENTRY");

  // Emit an entry point from C.
  emit_jmp32(s, (int64_t)t->trace_start);
  ir_ins *arg_ins = nullptr;
  for_each_leading_op(t, IR_ARG, arg_ins) {
    if (arg_ins->spill != SPILL_NONE) {
      abort();
    }
    if (arg_ins->reg != REG_NONE) {
      auto offset = (int32_t)arg_ins->data * 8;
      if (ins_uses_freg(arg_ins)) {
        emit_fmem_load(s, flonum_payload_offset - FLONUM_TAG, RTMP,
                       arg_ins->reg);
        // We need to typecheck to verify it is a flonum.
        emit_jcc32(s, JNE, (int64_t)t->snaps[0].patch_point);
        emit_cmp_constant(s, RTMP2, FLONUM_TAG);
        emit_and_constant(s, RTMP2, RTMP, TAG_MASK);
        COMMENT("  flonum typecheck");

        // Load ptr from stack.
        emit_mem_load(s, offset, RSTACK, RTMP);
      } else {
        emit_mem_load(s, offset, RSTACK, arg_ins->reg);
      }
    }
  }
  if (poly_entry) {
    emit_jmp32_patch_here(s, (int64_t)poly_entry->patch_point);
    __builtin___clear_cache((char *)poly_entry->patch_point,
                            (char *)poly_entry->patch_point + 16);
  }
  emit_mov(s, RSTACK, RARG1);
  emit_mov(s, RSTATE, RARG0);
  save_callee_regs(s);
  COMMENT("CENTRY");
}

static void emit_side_trace_entry(emit_state *s, trace *t) {
  // Emit register shuffle.
  par_copy *cpy = nullptr;
  ir_ins *pmov_ins = nullptr;
  for_each_leading_op(t, IR_PMOV, pmov_ins) {
    if (pmov_ins->spill != SPILL_NONE) {
      abort();
    }
    if (pmov_ins->reg != REG_NONE) {
      arrput(nullptr, cpy,
             ((par_copy){.from = pmov_ins->prev_reg, .to = pmov_ins->reg}));
    }
  }
  emit_serialized_moves(s, cpy, nullptr);
  COMMENT("PARALLEL COPY FROM PARENT:");

  // Install the side trace.
  emit_jmp32_patch_here(s, (int64_t)t->parent_snap->patch_point);
  __builtin___clear_cache((char *)t->parent_snap->patch_point,
                          (char *)t->parent_snap->patch_point + 16);
}
void emit_install_poly_root(emit_state *s, int64_t entry, const snap *snap) {}
static void emit_finish_snap_exits(emit_state *s, trace *t,
                                   int64_t exit_label) {
  // Emit even MORE snap exits.  We didn't have register allocation
  // previously, but now we do. Since these are slowpath exists, the extra
  // branches probably don't matter much.
  for (uint64_t i = arrlen(t->snaps) - 1; i > 0; i--) {
    snap *snap = &t->snaps[i - 1];
    emit_jmp32(s, exit_label);
    emit_snap(s, t, snap, true, nullptr);
    emit_jmp32_patch_here(s, (int64_t)t->snaps[i - 1].patch_point);
    COMMENT("Snap exit #%i", i - 1);
  }
}

trace_fn emit(trace *t, emit_state *s, record_state *record,
              const snap *poly_entry) {
  // Initialize asm emitter memory if not already done (once per process)
  emit_init(s);

  // Remember, we're emitting backwards! This makes the register
  // allocator much simpler to write, no state needs to be preserved.

  emit_writable_begin(s);
  memset(s->regs, 0, sizeof(s->regs));

  // Set up register allocator.
  bool reserved[MAX_REG] = {0};
  asm_mark_unallocatable(reserved);
  for (int i = 0; i < MAX_REG; i++) {
    s->regs[i].used = reserved[i];
  }
  // TODO move this back to asm backends?
  s->regs[FRTMP].used = true;
  s->next_spill = 0;

  // Emit a return-to-c stub.
  auto end = emit_offset(s);
  emit_exit_to_c(s);
  auto exit_label = emit_offset(s);

  // Exist stubs for all but the last. These are eventually replaced
  // by jumps to side traces as we emit them.  Otherwise we restore
  // state and jump to the C exit stub.
  emit_snapshot_exit_jumps(s, t->snaps);

  // Link to the next trace: Which is either ourselves (if a looping parent
  // trace), or another trace (if a side trace).
  ignoremap *loopback_regs = link_to_next_trace(s, t);

  emit_ir(s, t);

  // This is where the trace will start when other traces are linked to it.
  t->trace_start = emit_offset(s);

  if (!t->parent) {
    emit_root_trace_entry(s, t, loopback_regs, poly_entry);
  } else {
    emit_side_trace_entry(s, t);
  }

  auto entry = emit_offset(s);
  append_global_comment(s, entry, "ENTRY trace #%u (%s)", (unsigned)t->num,
                        t->parent ? "side" : "root");
  emit_finish_snap_exits(s, t, exit_label);
  auto start = emit_offset(s);

  emit_constant_pool(s);
  emit_writable_end(s);
  auto sz = end - start;
  if (verbose) {
    printf("Disassembly: %" PRId64 "\n", sz);
    arr_reverse(s->comments);
    disassemble((uint8_t *)start, sz, s->comments);
  }

  // Cleanup
  zone_free(&s->z);
  s->comments = nullptr;
  arrfree(loopback_regs);

  // Install debuginfo for gdb & linux perf tool.
  char funcname[256];
  char *dumpname = t->parent ? "SIDE" : "TRACE";
  snprintf(funcname, sizeof(funcname), "%s_%i", dumpname, t->num);
  register_jit_symbol((uint8_t *)start, (uint8_t *)entry, (uint8_t *)end,
                      funcname);
  // Call the built-in function to flush the cache for the specific range
  __builtin___clear_cache((char *)emit_offset(s), (char *)end);
  return (trace_fn)entry;
}
