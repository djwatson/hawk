#include <capstone/capstone.h> // for cs_insn, cs_close, cs_disasm, cs_free

#include "emit.h"

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "array.h"
#include "asm.h"
#include "comments.h"
#include "disassemble.h"
#include "gc.h"
#include "hawk.h"
#include "ir.h"
#include "jitdump.h"
#include "parallel_copy.h"
#include "profiler.h"
#include "record.h"
#include "regalloc.h"
#include "vm.h"
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
  if (jit_dump_flag) {
    jit_reader_add((int)(end - entry), (uint64_t)entry, name);
    jit_dump((int)(end - start), (uint64_t)start, name);
    perf_map((uint64_t)start, (uint64_t)(end - start), name);
  }
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

  auto start = (uint8_t *)emit_offset(s);

  emit_writable_begin(s);

  emit_push_regs(s, slowpath_regs, reg_cnt, true);
  emit_mov(s, RARG0, RET_REG);
  emit_mov64(s, RTMP, (int64_t)&gc_alloc);
  emit_call_reg(s, RTMP);

  emit_pop_regs(s, slowpath_regs, reg_cnt, true);
  emit_ret(s);

  auto end = emit_offset(s);
  s->alloc_slowpath = start;

  emit_writable_end(s);
  register_jit_symbol(start, s->alloc_slowpath, (uint8_t *)end, "GCslowpath");
  if (false && verbose) {
    printf("GC slowpath: %" PRId64 "\n", end - (long)start);
    disassemble(start, end - (long)start, nullptr);
  }
}

static inline bool ins_uses_freg(ir_ins const *ins) {
  return ins->type == FLONUM_TAG;
}

static inline bool is_fpr_reg(uint8_t reg) { return reg >= FPR_REG_START; }

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

  if (rhs.constant) {
    emit_cmp_constant(s, slot_reg(t, lhs), slot_const(t, rhs));
    return;
  }

  emit_cmp(s, slot_reg(t, lhs), slot_reg(t, rhs));
}

static void emit_arith_slots(emit_state *s, trace *t, uint8_t dst, slot lhs,
                             slot rhs, bool is_sub) {
  assert(!lhs.constant && "Left operand must be in a register");

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

  COMMENT("Emit stack guard check");
  label done = {0};
  emit_mem_load(s, (int32_t)offsetof(vm_state, stack_limit), RSTATE, RTMP);
  emit_cmp(s, RSTACK, RTMP);
  emit_jcc32(s, JL, &done);

  emit_push_regs(s, regs_to_save, regs_cnt, false);
  emit_mov(s, RARG1, RSTACK);
  emit_mov(s, RARG0, RSTATE);
  emit_mov64(s, RTMP, (intptr_t)&jit_expand_stack_slowpath);

  emit_call_reg(s, RTMP);
  emit_mov(s, RSTACK, RET_REG);
  emit_pop_regs(s, regs_to_save, regs_cnt, false);

  emit_label(s, &done);
  COMMENT("   end stack guard check");

  // Advance stack pointer after confirming we have space.
  emit_add_constant(s, RSTACK, RSTACK, (int64_t)snap->offset * 8);
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

static void emit_box_flonum(emit_state *s, int32_t stack_offset,
                            uint8_t fpr_reg, bool store_to_stack) {
  assert(s->alloc_slowpath);
  assert(is_fpr_reg(fpr_reg));
  emit_pop(s, RET_REG);
  emit_pop(s, RET_REG2);

  // Do stuff with allocated space.
  if (store_to_stack) {
    emit_store(s, stack_offset, RSTACK, RTMP);
  }
  emit_add_constant(s, RTMP, RTMP, FLONUM_TAG);
  emit_mov(s, RTMP, RET_REG);
  emit_fstore(s, flonum_payload_offset, RET_REG, fpr_reg);
  emit_store_constant(s, 0, RET_REG, FLONUM_TAG);

  label slow_continue_label = {0};
  emit_label(s, &slow_continue_label);
  // There WAS space, store new freelist end.
  emit_store(s, freelist_start_offset, RTMP, RET_REG2);
  emit_mov64(s, RTMP, (intptr_t)flonum_freelist);
  emit_mov(s, RET_REG2, RTMP);

  // No space, call slowpath
  label continue_label = {0};
  emit_label(s, &continue_label);
  emit_jmp32(s, &slow_continue_label);
  emit_call32(s, (int64_t)s->alloc_slowpath);
  emit_mov64(s, RET_REG, sizeof(flonum_s));

  // Check for fastpath space
  emit_jcc32(s, JLE, &continue_label);
  emit_cmp(s, RTMP, RET_REG2);
  emit_add_constant(s, RTMP, RTMP, (int32_t)sizeof(flonum_s));
  emit_mov(s, RTMP, RET_REG);
  emit_mem_load(s, freelist_end_offset, RTMP, RET_REG2);
  emit_mem_load(s, freelist_start_offset, RTMP, RET_REG);
  emit_mov64(s, RTMP, (intptr_t)flonum_freelist);

  emit_push(s, RET_REG2);
  emit_push(s, RET_REG);
}

static void emit_unbox_flonum(emit_state *s, uint8_t gpr_reg, uint8_t fpr_reg) {
  assert(!is_fpr_reg(gpr_reg));
  assert(is_fpr_reg(fpr_reg));
  emit_fmem_load(s, flonum_payload_offset - FLONUM_TAG, gpr_reg, fpr_reg);
}

static void emit_snap_store_flonum(emit_state *s, int32_t stack_offset,
                                   ir_ins *ins) {
  emit_box_flonum(s, stack_offset, ins->reg, true);
  COMMENT("Snap store flonum reg %s to slot %i", reg_names[ins->reg],
          stack_offset / 8);
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
      continue;
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
  par_copy *moves = serialize_parallel_copy(cpy, PAR_MOVE_MARKER);
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
      if (dst_fpr && src_fpr) {
        emit_fmov(s, to, from);
      } else if (!dst_fpr && src_fpr) {
        COMMENT("Box flonum %s to reg %s", reg_names[from], reg_names[to]);
        emit_box_flonum(s, 0, from, false);
        emit_mov(s, to, RTMP);
      } else if (dst_fpr && !src_fpr) {
        COMMENT("Unbox flonum %s to %s", reg_names[from], reg_names[to]);
        emit_unbox_flonum(s, from, to);
      } else {
        assert(!"Unsupported register move");
      }
    } else {
      emit_mov(s, to, from);
    }
  }
  emit_loopback_constants(s, loopback_regs);
  arrfree(cpy);
  arrfree(moves);
}

static void emit_loopback_stack_loads(emit_state *s, ignoremap *loopback_regs) {
  if (!loopback_regs) {
    return;
  }
  arr_for_each_idx(loopback_regs, i) {
    auto reg_map = &loopback_regs[i];
    if (!reg_map->needs_stack_load) {
      continue;
    }
    if (reg_map->target_reg == REG_NONE) {
      continue;
    }
    auto stack_off = (int32_t)reg_map->slot * 8;
    if (reg_map->type == FLONUM_TAG) {
      emit_fmem_load(s, 8 - FLONUM_TAG, RTMP, reg_map->target_reg);
      emit_mem_load(s, stack_off, RSTACK, RTMP);
      emit_mov(s, RTMP, reg_map->target_reg);
    } else {
      emit_mem_load(s, stack_off, RSTACK, reg_map->target_reg);
    }
  }
}
static void emit_typecheck(emit_state *s, trace *t, ir_ins *op,
                           int32_t cur_snap) {
  if (!op->guard) {
    return;
  }
  uint8_t reg = op->reg;
  if (op->op == IR_TYPECHECK) {
    reg = slot_reg(t, op->op1);
  }
  if (op->type == FIXNUM_TAG) {
    COMMENT("  typecheck fix");
    emit_test_constant(s, reg, TAG_MASK);
    emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
  } else if (op->type == CONS_TAG) {
    COMMENT("  typecheck cons");
    emit_mov(s, RTMP, reg);
    emit_and_constant(s, RTMP, RTMP, TAG_MASK);
    emit_cmp_constant(s, RTMP, CONS_TAG);
    emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
  } else if (op->type == FLONUM_TAG) {
    // These are already typechecked (and are in xmm register).
    COMMENT("  TODO typecheck flonum");
  } else {
    // TODO TODO TODO
    COMMENT("  TODO typecheck OTHER");
    /* abort(); */
  }
}

static ignoremap *collect_loopback_moves(emit_state *s, trace *exit_trace,
                                         trace *entry_trace, snap *exit_snap,
                                         snap *entry_snap, par_copy **cpy_out) {
  ignoremap *loopback_regs = nullptr;
  par_copy *cpy = nullptr;

  size_t entry_len = arrlen(entry_snap->slots);
  bool *entry_seen = entry_len ? calloc(entry_len, sizeof(bool)) : nullptr;

  arr_for_each_idx(exit_snap->slots, i) {
    auto exit_entry = &exit_snap->slots[i];
    uint16_t exit_slot = exit_entry->slot;
    int32_t exit_logical =
        (int32_t)exit_entry->slot - (int32_t)exit_snap->offset;
    size_t entry_idx = SIZE_MAX;
    arr_for_each_idx(entry_snap->slots, j) {
      auto candidate = &entry_snap->slots[j];
      uint16_t entry_slot = candidate->slot;
      if (exit_logical == (int32_t)entry_slot) {
        entry_idx = j;
        break;
      }
    }
    if (entry_idx != SIZE_MAX) {
      auto entry = &entry_snap->slots[entry_idx];
      ignoremap map = {.slot = exit_slot, .target_reg = REG_NONE};
      if (exit_entry->val.constant) {
        map.needs_constant = true;
        map.constant_value = slot_const(exit_trace, exit_entry->val);
      } else {
        map.reg = slot_reg(exit_trace, exit_entry->val);
        map.type = slot_ins(exit_trace, exit_entry->val)->type;
      }
      if (!entry->val.constant) {
        map.target_reg = slot_reg(entry_trace, entry->val);
        map.type = slot_ins(entry_trace, entry->val)->type;
      }
      entry_seen[entry_idx] = true;
      arrput(nullptr, loopback_regs, map);
      continue;
    }
  }

  arr_for_each_idx(entry_snap->slots, j) {
    if (entry_seen[j]) {
      continue;
    }
    auto entry = &entry_snap->slots[j];
    ignoremap map = {.slot = entry->slot, .target_reg = REG_NONE};
    if (entry->val.constant) {
      map.needs_constant = true;
      map.constant_value = slot_const(entry_trace, entry->val);
    } else {
      map.needs_stack_load = true;
      map.target_reg = slot_reg(entry_trace, entry->val);
      map.type = slot_ins(entry_trace, entry->val)->type;
    }
    arrput(nullptr, loopback_regs, map);
  }

  free(entry_seen);

  arr_for_each_idx(loopback_regs, i) {
    auto reg_map = &loopback_regs[i];
    if (reg_map->needs_constant) {
      continue;
    }
    if (reg_map->needs_stack_load) {
      if (reg_map->target_reg == REG_NONE) {
        abort();
      }
      continue;
    }
    if (reg_map->reg == REG_NONE || reg_map->target_reg == REG_NONE) {
      continue;
    }
    arrput(nullptr, cpy,
           ((par_copy){.from = reg_map->reg, .to = reg_map->target_reg}));
  }

  *cpy_out = cpy;
  return loopback_regs;
}

static void emit_snap(emit_state *s, trace *t, snap *snap, bool exit,
                      ignoremap *ignore) {

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

  emit_stack_offset_and_check(s, snap, ignore);
  // If this is an exiting snapshot (vs. a loop back)
  // then record exit PC & snapshot.
  if (exit) {
    emit_mov64(s, RET_REG2, (intptr_t)snap);
    emit_mov(s, RET_REG, RSTACK);
  }
}
// NOLINTEND(clang-analyzer-core.NullDereference)

static void emit_exit_to_c(emit_state *s) {
  COMMENT("CEXIT");
  restore_callee_regs(s);
  emit_ret(s);
}

static void emit_snapshot_exits(emit_state *s, trace *t, snap *snaps,
                                label *exit_label) {
  for (uint64_t i = 0; i < arrlen(snaps) - 1; i++) {
    COMMENT("Snap exit #%i", i);
    snap *snap = &snaps[i];
    emit_label(s, &snap->patch_point);
    emit_snap(s, t, snap, true, nullptr);
    emit_jmp32(s, exit_label);
  }
}

static void link_to_next_trace(emit_state *s, trace *t,
                               uint8_t entry_snap_idx) {
  auto cur_snap = arrlen(t->snaps) - 1;

  auto sn = &t->snaps[cur_snap];
  trace *linked_trace = t->link;
  snap *entry_snap = &linked_trace->snaps[entry_snap_idx];

  if (linked_trace == t) {
    COMMENT("Loopback (snap exit %i)", cur_snap);
  } else {
    COMMENT("Link to trace %i (snap exit %i)", t->link->num, cur_snap);
  }

  par_copy *cpy = nullptr;
  ignoremap *loopback_regs =
      collect_loopback_moves(s, t, linked_trace, sn, entry_snap, &cpy);
  // TODO is this duplicated?  Probably still need to adjust offset though.
  emit_snap(s, t, sn, false, loopback_regs);
  emit_loopback_stack_loads(s, loopback_regs);
  emit_serialized_moves(s, cpy, loopback_regs);
  arrfree(loopback_regs);

  label *target =
      entry_snap_idx == 1 ? &t->link->snap_entry_label : &t->link->trace_start;
  emit_jmp32(s, target);
}

static void emit_ir(emit_state *s, trace *t) {
  int32_t cur_snap = 0;

  for (int op_cnt_idx = 0; op_cnt_idx < arrlen(t->ins); op_cnt_idx++) {
    while (cur_snap < arrlen(t->snaps) &&
           t->snaps[cur_snap + 1].ir == op_cnt_idx) {
      if (cur_snap == 0) {
        emit_label(s, &t->snap_entry_label);
      }
      cur_snap++;
    }
    auto op = &t->ins[op_cnt_idx];

    COMMENT("%i %s", op_cnt_idx, ir_names[op->op]);
    switch (op->op) {
    case IR_GUARD_EQ:
    case IR_EQ: {
      emit_cmp_slots(s, t, op->op1, op->op2);
      emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
      break;
    }
    case IR_NE: {
      emit_cmp_slots(s, t, op->op1, op->op2);
      emit_jcc32(s, JE, &t->snaps[cur_snap].patch_point);
      break;
    }
    case IR_LOAD: {
      assert(!op->op1.constant);
      assert(op->op2.constant);
      int64_t offset_bytes =
          to_fixnum(t->consts[op->op2.loc]) + (int64_t)sizeof(gc_header);
      emit_mem_load(s, (int32_t)offset_bytes, slot_reg(t, op->op1), op->reg);
      emit_typecheck(s, t, op, cur_snap);
      break;
    }
    case IR_STORE: {
      ir_ins *ref = slot_ins(t, op->op1);

      auto val_reg = RTMP;
      if (!op->op2.constant) {
        val_reg = slot_reg(t, op->op2);
      }

      auto base_reg = slot_reg(t, ref->op1);
      if (ref->op2.constant) {
        // Offset is a constant.
        auto offset = slot_const(t, ref->op2) + (int64_t)(8 - op->type);
        // TODO check fits in int32_t.
        emit_store(s, (int32_t)offset, base_reg, val_reg);
      } else {
        // We need a tmp reg.
        // TODO: x64 supports index, base, const addressing, but other arches
        // don't

        // Offset is NOT a const, need additional offset + typed offset.
        emit_mov(s, op->reg, slot_reg(t, ref->op2));
        emit_add(s, op->reg, op->reg, base_reg);
        emit_store(s, 8 - op->type, base_reg, val_reg);
      }

      if (op->op2.constant) {
        emit_mov64(s, RTMP, slot_const(t, op->op2));
      }
      break;
    }
    case IR_REF: {
      break;
    }
    case IR_LT: {
      emit_cmp_slots(s, t, op->op1, op->op2);
      emit_jcc32(s, JGE, &t->snaps[cur_snap].patch_point);
      break;
    }
    case IR_GT: {
      emit_cmp_slots(s, t, op->op1, op->op2);
      emit_jcc32(s, JLE, &t->snaps[cur_snap].patch_point);
      break;
    }
    case IR_GTE: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_cmp(s, t, op);
      } else {
        emit_cmp_slots(s, t, op->op1, op->op2);
      }
      enum jcc_cond guard = (op->type == FLONUM_TAG) ? JB : JL;
      emit_jcc32(s, guard, &t->snaps[cur_snap].patch_point);
      break;
    }
    case IR_SUB: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_sub(s, t, op);
      } else {
        emit_arith_slots(s, t, op->reg, op->op1, op->op2, true);
        emit_typecheck(s, t, op, cur_snap);
      }
      break;
    }
    case IR_ADD: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_add(s, t, op);
      } else {
        // TODO: check for overflow
        emit_arith_slots(s, t, op->reg, op->op1, op->op2, false);
        emit_typecheck(s, t, op, cur_snap);
      }
      break;
    }
    case IR_SLOAD: {
      if (op->type == FLONUM_TAG) {
        // We need to typecheck to verify it is a flonum.
        // TODO if we had a spare register this would be more efficent.
        COMMENT("  flonum typecheck");
        emit_mem_load(s, (int32_t)op->data * 8, RSTACK, RTMP);
        emit_and_constant(s, RTMP, RTMP, TAG_MASK);
        emit_cmp_constant(s, RTMP, FLONUM_TAG);
        emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
        emit_mem_load(s, (int32_t)op->data * 8, RSTACK, RTMP);
        emit_fmem_load(s, 8 - FLONUM_TAG, RTMP, op->reg);
      } else {
        emit_mem_load(s, (int32_t)op->data * 8, RSTACK, op->reg);
      }
      emit_typecheck(s, t, op, cur_snap);
      break;
    }
    case IR_GGET: {
      emit_mov64(s, RTMP, slot_const(t, op->op1) - SYMBOL_TAG);
      emit_mem_load(s, 16, RTMP, op->reg);
      break;
    }
    case IR_RET: {
      // mov ra to a register

      // cmp stack[-1], jmp to snap if not equal
      emit_mem_load(s, -8, RSTACK, op->reg);
      emit_cmp_constant(s, op->reg, slot_const(t, op->op2));
      emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
      emit_sub_constant(s, RSTACK, RSTACK, slot_const(t, op->op1));

      break;
    }
    case IR_ALLOC: {
      assert(op->reg != REG_NONE);
      assert(op->op1.constant);
      assert(op->op2.constant);
      int64_t size_bytes = slot_const(t, op->op1) >> FIXNUM_SHIFT;
      assert((size_bytes & 7) == 0);
      uint64_t type_val = (uint64_t)(slot_const(t, op->op2) >> FIXNUM_SHIFT);
      uint8_t tag_bits = (uint8_t)(type_val & TAG_MASK);
      assert(s->alloc_slowpath);

      if (op->reg != RET_REG) {
        emit_push(s, RET_REG);
        emit_push(s, RET_REG);
      }
      emit_mov64(s, RET_REG, size_bytes);
      emit_call32(s, (int64_t)s->alloc_slowpath);
      emit_store_constant(s, 0, RET_REG, (int64_t)type_val);
      emit_add_constant(s, op->reg, RET_REG, tag_bits);
      if (op->reg != RET_REG) {
        emit_pop(s, RET_REG);
        emit_pop(s, RET_REG);
      }
      break;
    }
    case IR_ARG:
    case IR_NOP:
    case IR_PMOV:
      break;
    case IR_TYPECHECK: {
      emit_typecheck(s, t, op, cur_snap);
      if (op->reg == REG_NONE) {
      } else if (is_fpr_reg(op->reg)) {
        emit_unbox_flonum(s, slot_reg(t, op->op1), op->reg);
      } else {
        emit_mov(s, op->reg, slot_reg(t, op->op1));
      }
      break;
    }
    default: {
      printf("Can't jit op: %s\n", ir_names[op->op]);
      abort();
      // exit(-1);
    }
    }
    // TODO: maybe move emit_typecheck here, instead of each individual one.
    if (op->guard &&
        !(op->op == IR_ARG || op->op == IR_PMOV || op->op == IR_SLOAD ||
          op->op == IR_LOAD || op->op == IR_ALLOC || op->op == IR_TYPECHECK ||
          op->op == IR_SUB || op->op == IR_ADD)) {
      abort();
    }
  }
}

// Emit *two* entry points:
// One that loops back from the current trace
// One from c.
static void emit_root_trace_entry(emit_state *s, trace *t) {
  // Emit an entry point from C.
  COMMENT("CENTRY");
  save_callee_regs(s);
  emit_mov(s, RSTATE, RARG0);
  emit_mov(s, RSTACK, RARG1);

  ir_ins *arg_ins = nullptr;
  for_each_leading_op(t, IR_ARG, arg_ins) {
    if (arg_ins->spill != SPILL_NONE) {
      abort();
    }
    if (arg_ins->reg != REG_NONE) {
      auto offset = (int32_t)arg_ins->data * 8;
      assert(!ins_uses_freg(arg_ins));
      emit_mem_load(s, offset, RSTACK, arg_ins->reg);
    }
  }
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

  // TODO: Install the side trace with the label-based patching scheme.
}

trace_fn emit(trace *t, emit_state *s, record_state *record,
              const snap *poly_entry, uint8_t link_entry_snap) {
  // Initialize asm emitter memory if not already done (once per process)
  emit_init(s);

  // Allocate registers, print the IR in verbose mode.
  regalloc(t);
  if (verbose) {
    print_ir(t);
  }

  // Remember, we're emitting backwards! This makes the register
  // allocator much simpler to write, no state needs to be preserved.
  emit_writable_begin(s);

  // Emit a return-to-c stub.
  // TODO: could be shared by ALL traces
  auto start = emit_offset(s);

  if (!t->parent) {
    emit_root_trace_entry(s, t);
  } else {
    abort();
    /* emit_side_trace_entry(s, t); */
  }

  // This is where the trace will start when other traces are linked to it.
  // (without typechecking).
  emit_label(s, &t->trace_start);

  emit_ir(s, t);

  // Link to the next trace: Which is either ourselves (if a looping parent
  // trace), or another trace (if a side trace).
  link_to_next_trace(s, t, link_entry_snap);

  label exit_label = {0};
  // Exist stubs for all but the loopback (last). These restore the scheme stack
  // state, putting any in-register values back on the stack, and boxing
  // flonums.
  emit_snapshot_exits(s, t, t->snaps, &exit_label);

  emit_label(s, &exit_label);
  emit_exit_to_c(s);
  auto end = emit_offset(s);

  emit_constant_pool(s);
  emit_writable_end(s);

  auto sz = end - start;
  if (verbose) {
    printf("Disassembly: %" PRId64 "\n", sz);
    disassemble((uint8_t *)start, sz, s->comments);
  }

  // Cleanup
  zone_free(&s->z);
  s->comments = nullptr;

  // Install debuginfo for gdb & linux perf tool.
  char funcname[256];
  char *dumpname = t->parent ? "SIDE" : "TRACE";
  snprintf(funcname, sizeof(funcname), "%s_%i", dumpname, t->num);
  register_jit_symbol((uint8_t *)start, (uint8_t *)start, (uint8_t *)end,
                      funcname);
  // Call the built-in function to flush the cache for the specific range
  __builtin___clear_cache((char *)emit_offset(s), (char *)end);
  return (trace_fn)start;
}
