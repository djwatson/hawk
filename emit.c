#include <capstone/capstone.h> // for cs_insn, cs_close, cs_disasm, cs_free

#include "emit.h"

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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

static gc_obj spills[256];

static void register_jit_symbol(uint8_t *start, uint8_t *entry, uint8_t *end,
                                const char *name) {
  profiler_register_jit_symbol(start, end, name);
  if (jit_dump_flag) {
    jit_reader_add((int)(end - entry), (uint64_t)entry, name);
    jit_dump((int)(end - start), (uint64_t)start, name);
    perf_map((uint64_t)start, (uint64_t)(end - start), name);
  }
}

static inline void *gc_alloc_tagged(uint64_t tagged_sz) {
  return gc_alloc((uint64_t)(tagged_sz >> FIXNUM_SHIFT));
}

// Slowpath: RET_REG is tagged size on entry, allocation result on return.
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
  emit_mov64(s, RTMP, (int64_t)&gc_alloc_tagged);
  emit_call_reg(s, RTMP);

  emit_pop_regs(s, slowpath_regs, reg_cnt, true);
  emit_ret(s);

  auto end = emit_offset(s);
  s->alloc_slowpath = start;

  emit_writable_end(s);
  register_jit_symbol(start, s->alloc_slowpath, (uint8_t *)end, "GCslowpath");

  /* if (verbose) { */
  /*   printf("GC slowpath: %" PRId64 "\n", end - (long)start); */
  /*   disassemble(start, end - (long)start, nullptr); */
  /* } */
}

static inline bool ins_uses_freg(ir_ins const *ins) {
  return ins->type == FLONUM_TAG;
}

static inline bool is_fpr_reg(uint8_t reg) { return reg >= FPR_REG_START; }
static dense_loc_entry snap_entry_loc(trace const *t, uint16_t snap_idx,
                                      size_t entry_idx);
static const uint8_t PAR_MOVE_MARKER = UINT8_MAX;

static inline ir_ins *slot_ins(trace *t, slot v) {
  assert(!v.constant);
  return &t->ins[v.loc];
}

static inline int64_t slot_const(trace *t, slot v) {
  assert(v.constant);
  return t->consts[v.loc].value;
}

static inline int32_t spill_offset(uint8_t spill) {
  assert(spill != SPILL_NONE);
  return (int32_t)spill * 8;
}

static uint8_t ir_input_reg(trace const *t, regalloc2_result const *r,
                            uint16_t ir_idx, uint8_t arg_idx) {
  auto ins = &t->ins[ir_idx];
  size_t in_idx = r->ir_id_to_dense_map[ir_idx];

  if (arg_idx == 0) {
    if (ir_ins_types[ins->op] == IR_ARG_IR_NONE ||
        ir_ins_types[ins->op] == IR_ARG_IR_IR ||
        ir_ins_types[ins->op] == IR_ARG_IR_ADDR) {
      if (ins->op1.constant) {
        if (ins->op == IR_RET) {
          auto loc = r->dense_locs[in_idx++];
          assert(loc.kind == LOC_REG);
          return loc.reg;
        }
        return REG_NONE;
      }
      auto loc = r->dense_locs[in_idx++];
      assert(loc.kind == LOC_REG);
      return loc.reg;
    }
    return REG_NONE;
  }

  if (arg_idx == 1 && ir_ins_types[ins->op] == IR_ARG_IR_IR) {
    if (!ins->op1.constant) {
      in_idx++;
    }
    if (ins->op2.constant) {
      return REG_NONE;
    }
    auto loc = r->dense_locs[in_idx++];
    assert(loc.kind == LOC_REG);
    return loc.reg;
  }

  return REG_NONE;
}

static dense_loc_entry snap_entry_loc(trace const *t, uint16_t snap_idx,
                                      size_t entry_idx) {
  auto sn = &t->snaps[snap_idx];
  auto entry = &sn->slots[entry_idx];
  assert(!entry->val.constant);
  auto ins = &t->ins[entry->val.loc];
  if (ins->spill != SPILL_NONE) {
    return (dense_loc_entry){.kind = LOC_SPILL,
                             .reg = REG_NONE,
                             .spill = ins->spill,
                             .value_id = entry->val.loc};
  }
  assert(ins->reg != REG_NONE);
  return (dense_loc_entry){.kind = LOC_REG,
                           .reg = ins->reg,
                           .spill = SPILL_NONE,
                           .value_id = entry->val.loc};
}

static uint8_t ir_output_reg(trace const *t, uint16_t ir_idx) {
  return t->ins[ir_idx].reg;
}

static void emit_cmp_regs(emit_state *s, trace *t, uint8_t lhs_reg, slot rhs,
                          uint8_t rhs_reg) {
  assert(lhs_reg != REG_NONE);
  if (rhs.constant) {
    emit_cmp_constant(s, lhs_reg, slot_const(t, rhs));
    return;
  }
  assert(rhs_reg != REG_NONE);
  emit_cmp(s, lhs_reg, rhs_reg);
}

static void emit_arith_regs(emit_state *s, trace *t, uint8_t dst,
                            uint8_t lhs_reg, slot rhs, uint8_t rhs_reg,
                            bool is_sub) {
  assert(lhs_reg != REG_NONE);

  if (rhs.constant) {
    if (is_sub) {
      emit_sub_constant(s, dst, lhs_reg, slot_const(t, rhs));
    } else {
      emit_add_constant(s, dst, lhs_reg, slot_const(t, rhs));
    }
  } else {
    assert(rhs_reg != REG_NONE);
    if (is_sub) {
      emit_sub(s, dst, lhs_reg, rhs_reg);
    } else {
      emit_add(s, dst, lhs_reg, rhs_reg);
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

static __attribute__((preserve_all))
gc_obj *jit_expand_stack_slowpath(vm_state *state, gc_obj *stack) {
  expand_stack(state, &stack);
  return stack;
}

#define COMMENT(...) comment_append(emit_offset(s), &s->comments, __VA_ARGS__)

typedef struct {
  uint16_t slot;
  uint8_t target_reg;
} load_entry;

typedef struct {
  uint8_t target_reg;
  int64_t constant_value;
} const_entry;

static inline void add_entry_mapping(trace *entry_trace, snap_entry *entry,
                                     uint16_t slot, dense_loc_entry entry_loc,
                                     load_entry **loads, const_entry **consts) {
  (void)entry_loc;
  (void)consts;
  if (entry->val.constant) {
    return;
  }
  auto ins = &entry_trace->ins[entry->val.loc];
  uint8_t target_reg = ins->reg;
  if (target_reg != REG_NONE) {
    arrput(*loads, ((load_entry){.slot = slot, .target_reg = target_reg}));
  }
}

// NOLINTBEGIN(clang-analyzer-core.NullDereference)
static size_t collect_regs_to_preserve(uint8_t const *regs_in, size_t len,
                                       uint8_t regs[MAX_REG]) {
  size_t count = 0;
  bool added[MAX_REG] = {0};
  for (size_t i = 0; i < len; i++) {
    uint8_t reg = regs_in[i];
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
                                        uint8_t const *regs_in) {
  if (!snap->offset) {
    return;
  }
  uint8_t regs_to_save[MAX_REG];
  size_t regs_cnt =
      collect_regs_to_preserve(regs_in, arrlen(regs_in), regs_to_save);

  COMMENT("Emit stack guard check");
  label done = {};
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

static void emit_flonum_sub(emit_state *s, trace *t, uint8_t dst, ir_ins *op,
                            uint8_t lhs_reg, uint8_t rhs_reg) {
  assert(is_fpr_reg(dst));
  if (op->op2.constant) {
    emit_fsub_constant(s, dst, lhs_reg, slot_flonum_constant(t, op->op2));
    return;
  }
  if (op->op1.constant) {
    emit_fmov_constant(s, FRTMP, slot_flonum_constant(t, op->op1));
    emit_fsub(s, dst, FRTMP, rhs_reg);
    return;
  }
  emit_fsub(s, dst, lhs_reg, rhs_reg);
}

static void emit_flonum_cmp(emit_state *s, trace *t, ir_ins *op,
                            uint8_t lhs_reg, uint8_t rhs_reg) {
  if (op->op2.constant) {
    emit_fcmp_constant(s, lhs_reg, slot_flonum_constant(t, op->op2));
    return;
  }
  if (op->op1.constant) {
    emit_fmov_constant(s, FRTMP, slot_flonum_constant(t, op->op1));
    emit_fcmp(s, FRTMP, rhs_reg);
    return;
  }
  emit_fcmp(s, lhs_reg, rhs_reg);
}
static void emit_flonum_add(emit_state *s, trace *t, uint8_t dst, ir_ins *op,
                            uint8_t lhs_reg, uint8_t rhs_reg) {
  assert(is_fpr_reg(dst));
  if (op->op2.constant) {
    emit_fadd_constant(s, dst, lhs_reg, slot_flonum_constant(t, op->op2));
    return;
  }
  if (op->op1.constant) {
    emit_fmov_constant(s, FRTMP, slot_flonum_constant(t, op->op1));
    emit_fadd(s, dst, FRTMP, rhs_reg);
    return;
  }
  emit_fadd(s, dst, lhs_reg, rhs_reg);
}

static void emit_flonum_mul(emit_state *s, trace *t, uint8_t dst, ir_ins *op,
                            uint8_t lhs_reg, uint8_t rhs_reg) {
  assert(is_fpr_reg(dst));
  if (op->op2.constant) {
    emit_fmov_constant(s, FRTMP, slot_flonum_constant(t, op->op2));
    emit_fmul(s, dst, lhs_reg, FRTMP);
    return;
  }
  if (op->op1.constant) {
    emit_fmov_constant(s, FRTMP, slot_flonum_constant(t, op->op1));
    emit_fmul(s, dst, FRTMP, rhs_reg);
    return;
  }
  emit_fmul(s, dst, lhs_reg, rhs_reg);
}

static void emit_flonum_div(emit_state *s, trace *t, uint8_t dst, ir_ins *op,
                            uint8_t lhs_reg, uint8_t rhs_reg) {
  assert(is_fpr_reg(dst));
  if (op->op2.constant) {
    emit_fmov_constant(s, FRTMP, slot_flonum_constant(t, op->op2));
    emit_fdiv(s, dst, lhs_reg, FRTMP);
    return;
  }
  if (op->op1.constant) {
    emit_fmov_constant(s, FRTMP, slot_flonum_constant(t, op->op1));
    emit_fdiv(s, dst, FRTMP, rhs_reg);
    return;
  }
  emit_fdiv(s, dst, lhs_reg, rhs_reg);
}

static void emit_flonum_quotient(emit_state *s, trace *t, uint8_t dst,
                                 ir_ins *op, uint8_t lhs_reg, uint8_t rhs_reg) {
  emit_flonum_div(s, t, dst, op, lhs_reg, rhs_reg);
  emit_double_to_int64_trunc(s, RTMP, dst);
  emit_int64_to_double(s, dst, RTMP);
}

static void emit_box_flonum(emit_state *s, int32_t stack_offset,
                            uint8_t fpr_reg, bool store_to_stack) {
  assert(s->alloc_slowpath);
  assert(is_fpr_reg(fpr_reg));

  label continue_label = {};
  label slow_continue_label = {};

  emit_push(s, RET_REG);
  emit_push(s, RET_REG2);

  // Check for fastpath space
  emit_mov64(s, RTMP, (intptr_t)flonum_freelist);
  emit_mem_load(s, freelist_start_offset, RTMP, RET_REG);
  emit_mem_load(s, freelist_end_offset, RTMP, RET_REG2);
  emit_mov(s, RTMP, RET_REG);
  emit_add_constant(s, RTMP, RTMP, (int32_t)sizeof(flonum_s));
  emit_cmp(s, RTMP, RET_REG2);
  emit_jcc32(s, JLE, &continue_label);

  // No space, call slowpath
  emit_mov64(s, RET_REG, TAG_FIXNUM_VALUE(sizeof(flonum_s)));
  emit_call32(s, (int64_t)s->alloc_slowpath);
  emit_jmp32(s, &slow_continue_label);
  emit_label(s, &continue_label);

  emit_mov(s, RET_REG2, RTMP);
  emit_mov64(s, RTMP, (intptr_t)flonum_freelist);
  emit_store(s, freelist_start_offset, RTMP, RET_REG2);

  // There WAS space, store new freelist end.
  emit_label(s, &slow_continue_label);

  emit_store_constant(s, 0, RET_REG, FLONUM_TAG);
  emit_fstore(s, flonum_payload_offset, RET_REG, fpr_reg);
  emit_mov(s, RTMP, RET_REG);
  emit_add_constant(s, RTMP, RTMP, FLONUM_TAG);

  // Do stuff with allocated space.
  if (store_to_stack) {
    emit_store(s, stack_offset, RSTACK, RTMP);
  }
  emit_pop(s, RET_REG2);
  emit_pop(s, RET_REG);
  COMMENT("   end box flonum %s", reg_names[fpr_reg]);
}

static void emit_unbox_flonum(emit_state *s, uint8_t gpr_reg, uint8_t fpr_reg) {
  assert(!is_fpr_reg(gpr_reg));
  assert(is_fpr_reg(fpr_reg));
  emit_fmem_load(s, flonum_payload_offset - FLONUM_TAG, gpr_reg, fpr_reg);
}

static void emit_loopback_constants(emit_state *s, const_entry *consts) {
  arr_for_each_idx(consts, i) {
    auto map = &consts[i];
    assert(map->target_reg != REG_NONE);
    if (is_fpr_reg(map->target_reg)) {
      emit_fmov_constant(s, map->target_reg,
                         to_flonum((gc_obj){.value = map->constant_value})->x);
    } else {
      emit_mov64(s, map->target_reg, map->constant_value);
    }
  }
}

static uint8_t resolve_tmp_reg(uint8_t peer) {
  if (peer != PAR_MOVE_MARKER && is_fpr_reg(peer)) {
    return FRTMP;
  }
  return RTMP;
}

static void emit_serialized_moves(emit_state *s, par_copy *cpy) {
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
  arrfree(cpy);
  arrfree(moves);
}

static void emit_loopback_stack_loads(emit_state *s, load_entry *loads) {
  arr_for_each_idx(loads, i) {
    auto reg_map = &loads[i];
    assert(reg_map->target_reg != REG_NONE);
    auto stack_off = (int32_t)reg_map->slot * 8;
    if (is_fpr_reg(reg_map->target_reg)) {
      // This has already been typechecked as a flonum in record.c
      // ensure_args_match_trace, otherwise we would have picked a
      // generic entry point with a GPR boxed flonum.
      emit_mem_load(s, stack_off, RSTACK, RTMP);
      emit_fmem_load(s, 8 - FLONUM_TAG, RTMP, reg_map->target_reg);
    } else {
      emit_mem_load(s, stack_off, RSTACK, reg_map->target_reg);
    }
  }
}

static void emit_loopback_entry_spills(emit_state *s, trace *entry_trace,
                                       uint16_t entry_snap_idx) {
  auto entry_snap = &entry_trace->snaps[entry_snap_idx];
  arr_for_each_idx(entry_snap->slots, i) {
    auto entry = &entry_snap->slots[i];
    if (entry->val.constant) {
      continue;
    }
    auto ins = &entry_trace->ins[entry->val.loc];
    if (ins->spill == SPILL_NONE) {
      continue;
    }
    if (ins->reg == REG_NONE) {
      continue;
    }

    emit_mov64(s, RTMP, (intptr_t)spills);
    if (ins->type == FLONUM_TAG) {
      emit_fstore(s, spill_offset(ins->spill), RTMP, ins->reg);
    } else {
      emit_store(s, spill_offset(ins->spill), RTMP, ins->reg);
    }
  }
}

static void emit_typecheck(emit_state *s, trace *t, ir_ins *op,
                           int32_t cur_snap, uint8_t reg) {
  if (!op->guard) {
    return;
  }
  // TODO: some of these the code could be merged
  if (op->type == FIXNUM_TAG) {
    COMMENT("  typecheck fix");
    emit_test_constant(s, reg, TAG_MASK);
    emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
  } else if (op->type == CONS_TAG || op->type == VECTOR_TAG ||
             op->type == SYMBOL_TAG) {
    COMMENT("  typecheck %s", low_tag_names[op->type]);
    emit_mov(s, RTMP, reg);
    emit_and_constant(s, RTMP, RTMP, TAG_MASK);
    emit_cmp_constant(s, RTMP, op->type);
    emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
  } else if (op->type == FLONUM_TAG) {
    if (!is_fpr_reg(reg)) {
      COMMENT("  typecheck flonum");
      emit_mov(s, RTMP, reg);
      emit_and_constant(s, RTMP, RTMP, TAG_MASK);
      emit_cmp_constant(s, RTMP, FLONUM_TAG);
      emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
    }
  } else if (op->type == FUNC_TAG) {
    // func loads ONLY happen from closure loads, no need to typecheck.
  } else if ((op->type & TAG_MASK) == LITERAL_TAG) {
    // Literal or other immediate types: compare full immediate byte.
    uint8_t want_tag = (uint8_t)(op->type & IMMEDIATE_MASK);
    COMMENT("  typecheck literal");
    emit_mov(s, RTMP, reg);
    emit_and_constant(s, RTMP, RTMP, IMMEDIATE_MASK);
    emit_cmp_constant(s, RTMP, want_tag);
    emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
  } else {
    abort();
  }
}

static void collect_loopback_moves(trace *exit_trace, uint16_t exit_snap_idx,
                                   trace *entry_trace, uint16_t entry_snap_idx,
                                   par_copy **cpy_out, const_entry **consts_out,
                                   load_entry **loads_out,
                                   uint16_t **ignore_slots_out,
                                   uint8_t **regs_out) {
  const_entry *consts = nullptr;
  load_entry *loads = nullptr;
  par_copy *cpy = nullptr;
  uint16_t *ignore_slots = nullptr;
  uint8_t *regs = nullptr;

  auto exit_snap = &exit_trace->snaps[exit_snap_idx];
  auto entry_snap = &entry_trace->snaps[entry_snap_idx];
  size_t exit_len = arrlen(exit_snap->slots);
  size_t entry_len = arrlen(entry_snap->slots);
  size_t i = 0;
  size_t j = 0;
  while (i < exit_len && j < entry_len) {
    auto exit_entry = &exit_snap->slots[i];
    uint16_t exit_slot = exit_entry->slot;
    int32_t exit_logical =
        (int32_t)exit_entry->slot - (int32_t)exit_snap->offset;
    auto entry = &entry_snap->slots[j];
    uint16_t entry_slot = entry->slot;

    if (exit_logical == (int32_t)entry_slot) {
      dense_loc_entry exit_loc = {0};
      dense_loc_entry entry_loc = {0};
      uint8_t entry_reg = REG_NONE;
      if (!exit_entry->val.constant) {
        exit_loc = snap_entry_loc(exit_trace, exit_snap_idx, i);
      }
      if (!entry->val.constant) {
        entry_loc = snap_entry_loc(entry_trace, entry_snap_idx, j);
        entry_reg = entry_trace->ins[entry->val.loc].reg;
        if (entry_reg == REG_NONE && entry_loc.kind == LOC_REG) {
          entry_reg = entry_loc.reg;
        }
      }

      if (!exit_entry->val.constant && exit_loc.kind == LOC_REG) {
        uint8_t exit_reg = exit_loc.reg;
        arrput(regs, exit_reg);
      }

      if (exit_entry->val.constant && !entry->val.constant &&
          entry_reg != REG_NONE) {
        arrput(consts, ((const_entry){.target_reg = entry_reg,
                                      .constant_value = slot_const(
                                          exit_trace, exit_entry->val)}));
      } else if (!exit_entry->val.constant && !entry->val.constant &&
                 entry_reg != REG_NONE) {
        if (exit_loc.kind == LOC_REG) {
          if (exit_loc.reg != entry_reg) {
            arrput(cpy, ((par_copy){.from = exit_loc.reg, .to = entry_reg}));
          }
        } else {
          arrput(loads,
                 ((load_entry){.slot = entry_slot, .target_reg = entry_reg}));
        }
      }

      i++;
      j++;
      continue;
    }

    if (exit_logical < (int32_t)entry_slot) {
      // exit slot not present in entry; skip it
      i++;
      continue;
    }

    // entry slot lower than exit logical: unmatched entry -> stack load/const
    dense_loc_entry entry_loc = {0};
    if (!entry->val.constant) {
      entry_loc = snap_entry_loc(entry_trace, entry_snap_idx, j);
    }
    add_entry_mapping(entry_trace, entry, entry_slot, entry_loc, &loads,
                      &consts);
    j++;
  }

  // Remaining unmatched entry slots.
  while (j < entry_len) {
    auto entry = &entry_snap->slots[j];
    dense_loc_entry entry_loc = {0};
    if (!entry->val.constant) {
      entry_loc = snap_entry_loc(entry_trace, entry_snap_idx, j);
    }
    add_entry_mapping(entry_trace, entry, entry->slot, entry_loc, &loads,
                      &consts);
    j++;
  }

  *cpy_out = cpy;
  *consts_out = consts;
  *loads_out = loads;
  *ignore_slots_out = ignore_slots;
  *regs_out = regs;
}

static void emit_snap_store_entry(emit_state *s, trace *t,
                                  regalloc2_result const *regmap,
                                  uint16_t snap_idx, size_t entry_idx,
                                  snap_entry const *entry) {
  (void)regmap;
  auto stack_offset = (int32_t)entry->slot * 8;
  if (entry->val.constant) {
    emit_store_constant(s, stack_offset, RSTACK, slot_const(t, entry->val));
    return;
  }

  auto ins = &t->ins[entry->val.loc];
  auto loc = snap_entry_loc(t, snap_idx, entry_idx);
  uint8_t val_reg = REG_NONE;
  if (loc.kind == LOC_SPILL) {
    emit_mov64(s, RTMP, (intptr_t)spills);
    if (ins->type == FLONUM_TAG) {
      emit_fmem_load(s, spill_offset(loc.spill), RTMP, FRTMP);
      val_reg = FRTMP;
    } else {
      emit_mem_load(s, spill_offset(loc.spill), RTMP, RTMP);
      val_reg = RTMP;
    }
  } else {
    val_reg = loc.reg;
  }

  if (ins->type == FLONUM_TAG) {
    COMMENT("Snap store flonum reg %s to slot %i", reg_names[val_reg],
            stack_offset / 8);
    emit_box_flonum(s, stack_offset, val_reg, true);
  } else {
    emit_store(s, stack_offset, RSTACK, val_reg);
  }
}

static void emit_snap(emit_state *s, trace *t, regalloc2_result const *regmap,
                      uint16_t snap_idx, bool exit, uint16_t *ignore_slots,
                      uint8_t *regs_in) {
  auto snap = &t->snaps[snap_idx];

  arr_for_each_idx(snap->slots, j) {
    bool ignored = false;
    for (size_t i = 0; i < arrlen(ignore_slots); i++) {
      if (snap->slots[j].slot == ignore_slots[i]) {
        ignored = true;
        break;
      }
    }
    if (!ignored) {
      emit_snap_store_entry(s, t, regmap, snap_idx, j, &snap->slots[j]);
    }
  }

  emit_stack_offset_and_check(s, snap, regs_in);
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

static void emit_snapshot_exits(emit_state *s, trace *t,
                                regalloc2_result const *regmap, snap *snaps,
                                label *exit_label) {
  // There will always be at least two snapshots.  Don't write the last, it's
  // the loopback snap.
  for (uint64_t i = 0; i < arrlen(snaps) - 1; i++) {
    COMMENT("Snap exit #%i", i);
    snap *snap = &snaps[i];
    emit_label(s, &snap->patch_point);
    emit_snap(s, t, regmap, (uint16_t)i, true, nullptr, nullptr);
    emit_jmp32(s, exit_label);
  }
}

static void link_to_next_trace(emit_state *s, trace *t,
                               regalloc2_result const *regmap,
                               uint8_t entry_snap_idx) {
  auto cur_snap = (uint16_t)(arrlen(t->snaps) - 1);

  trace *linked_trace = t->link;

  if (linked_trace == t) {
    COMMENT("Loopback (snap exit %i)", cur_snap);
  } else {
    COMMENT("Link to trace %i (snap exit %i)", t->link->num, cur_snap);
  }

  // Reconcile exit snapshot to entry snapshot:
  // 1) both en-registered, then we do a parallel move
  // 2) constants we load
  // 3) stack loads needed (in entry but not exit).
  // 4) All the above get put in ignore_slots, and
  //    we emit_snap as normal, ignoring all those slots that we handle
  //    manually.
  // 5) We also have a list of registers that need preserving if we have
  //    to take a slowpath in expand_stack_slowpath. (TODO cleanup)
  par_copy *cpy = nullptr;
  const_entry *consts = nullptr;
  load_entry *loads = nullptr;
  uint16_t *ignore_slots = nullptr;
  uint8_t *regs_to_preserve = nullptr;
  collect_loopback_moves(t, cur_snap, linked_trace, entry_snap_idx, &cpy,
                         &consts, &loads, &ignore_slots, &regs_to_preserve);
  emit_snap(s, t, regmap, cur_snap, false, ignore_slots, regs_to_preserve);
  // Execute reg->reg reconciliation before stack loads so load targets do not
  // clobber move sources from the exit state.
  emit_serialized_moves(s, cpy);
  emit_loopback_stack_loads(s, loads);
  emit_loopback_constants(s, consts);
  emit_loopback_entry_spills(s, linked_trace, entry_snap_idx);
  arrfree(ignore_slots);
  arrfree(regs_to_preserve);
  arrfree(loads);
  arrfree(consts);

  label *target =
      entry_snap_idx == 1 ? &t->link->snap_entry_label : &t->link->trace_start;
  emit_jmp32(s, target);
}

static void emit_reload_events(emit_state *s, trace *t,
                               regalloc2_result const *regmap,
                               uint16_t ir_idx) {
  arr_for_each_idx(regmap->reload_ops, eidx) {
    auto e = regmap->reload_ops[eidx];
    if (e.ir_idx != ir_idx) {
      continue;
    }
    auto value = &t->ins[e.value_id];
    assert(value->spill != SPILL_NONE);
    COMMENT("RELOAD op %u to reg %s", e.value_id, reg_names[e.reg]);
    emit_mov64(s, RTMP, (intptr_t)spills);
    if (value->type == FLONUM_TAG) {
      emit_fmem_load(s, spill_offset(value->spill), RTMP, e.reg);
    } else {
      emit_mem_load(s, spill_offset(value->spill), RTMP, e.reg);
    }
  }
}

static void emit_ir(emit_state *s, trace *t, regalloc2_result const *regmap) {
  int32_t cur_snap = 0;

  for (uint16_t op_cnt_idx = 0; op_cnt_idx < arrlen(t->ins); op_cnt_idx++) {
    uint8_t arg0_reg = ir_input_reg(t, regmap, op_cnt_idx, 0);
    uint8_t arg1_reg = ir_input_reg(t, regmap, op_cnt_idx, 1);
    while ((size_t)(cur_snap + 1) < arrlen(t->snaps) &&
           t->snaps[cur_snap + 1].ir == op_cnt_idx) {
      if (cur_snap == 0) {
        emit_label(s, &t->snap_entry_label);
      }
      cur_snap++;
    }
    auto op = &t->ins[op_cnt_idx];
    uint8_t out_reg = op->reg;
    uint8_t dst_reg = out_reg;
    if (dst_reg == REG_NONE) {
      dst_reg = ins_uses_freg(op) ? FRTMP : RTMP;
    }

    COMMENT("%i %s", op_cnt_idx, ir_names[op->op]);
    emit_reload_events(s, t, regmap, op_cnt_idx);

    switch (op->op) {
    case IR_GUARD_EQ:
    case IR_EQ: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_cmp(s, t, op, arg0_reg, arg1_reg);
        emit_jcc32(s, JP, &t->snaps[cur_snap].patch_point);
        emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
      } else {
        emit_cmp_regs(s, t, arg0_reg, op->op2, arg1_reg);
        emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
      }
      break;
    }
    case IR_GUARD_NEQ:
    case IR_NE: {
      if (op->type == FLONUM_TAG) {
        label done = {};
        emit_flonum_cmp(s, t, op, arg0_reg, arg1_reg);
        emit_jcc32(s, JP, &done);
        emit_jcc32(s, JE, &t->snaps[cur_snap].patch_point);
        emit_label(s, &done);
      } else {
        emit_cmp_regs(s, t, arg0_reg, op->op2, arg1_reg);
        emit_jcc32(s, JE, &t->snaps[cur_snap].patch_point);
      }
      break;
    }
    case IR_LOAD: {
      uint8_t base_reg = arg0_reg;
      if (op->op1.constant) {
        // Materialize constant base object pointer for direct loads.
        base_reg = RTMP;
        emit_mov64(s, base_reg, slot_const(t, op->op1));
      }
      uint8_t base_type = op->op1.constant ? get_tag(t->consts[op->op1.loc])
                                           : slot_ins(t, op->op1)->type;
      int32_t typed_offset = (int32_t)((int64_t)sizeof(gc_header) - base_type);
      if (op->type == FLONUM_TAG) {
        // Slot contains a tagged flonum gc_obj; load object first, then payload.
        // Prefer the dedicated secondary scratch register when available.
        uint8_t obj_reg = asm_rtmp2_reserved() ? RTMP2 : RET_REG2;
        if (op->op2.constant) {
          int64_t offset_bytes = t->consts[op->op2.loc].value + typed_offset;
          emit_mem_load(s, (int32_t)offset_bytes, base_reg, obj_reg);
        } else {
          emit_add(s, obj_reg, arg1_reg, base_reg);
          emit_mem_load(s, typed_offset, obj_reg, obj_reg);
        }
        emit_typecheck(s, t, op, cur_snap, obj_reg);
        emit_fmem_load(s, 8 - FLONUM_TAG, obj_reg, dst_reg);
      } else {
        if (op->op2.constant) {
          int64_t offset_bytes = t->consts[op->op2.loc].value + typed_offset;
          emit_mem_load(s, (int32_t)offset_bytes, base_reg, dst_reg);
        } else {
          emit_add(s, RTMP, arg1_reg, base_reg);
          emit_mem_load(s, typed_offset, RTMP, dst_reg);
        }
        emit_typecheck(s, t, op, cur_snap, dst_reg);
      }
      break;
    }
    case IR_STORE: {
      ir_ins *ref = slot_ins(t, op->op1);
      uint16_t ref_idx = op->op1.loc;

      auto val_reg = RTMP;
      if (op->op2.constant) {
        emit_mov64(s, val_reg, slot_const(t, op->op2));
      } else {
        // IR_STORE materializes inputs as [ref args..., value].
        // So arg1_reg is not the value reg when REF has two args.
        size_t in_idx = regmap->ir_id_to_dense_map[op_cnt_idx];
        size_t ref_arg_cnt = 0;
        if (!ref->op1.constant) {
          ref_arg_cnt++;
        }
        if (!ref->op2.constant) {
          ref_arg_cnt++;
        }
        auto val_loc = regmap->dense_locs[in_idx + ref_arg_cnt];
        assert(val_loc.kind == LOC_REG);
        val_reg = val_loc.reg;
        if (is_fpr_reg(val_reg)) {
          // Object stores are tagged gc_obj slots; box flonum payload first.
          emit_box_flonum(s, 0, val_reg, false);
          val_reg = RTMP;
        }
      }

      uint8_t base_reg = ir_input_reg(t, regmap, ref_idx, 0);
      if (ref->op1.constant) {
        // REF base can be a constant object (e.g. global vector).
        // Materialize it explicitly since constant args have no input reg.
        base_reg = RTMP2;
        emit_mov64(s, base_reg, slot_const(t, ref->op1));
      }
      if (ref->op2.constant) {
        // Offset is a constant.
        auto offset = slot_const(t, ref->op2) + (int64_t)(8 - op->type);
        assert((int32_t)offset == offset);
        emit_store(s, (int32_t)offset, base_reg, val_reg);
      } else {
        // We need a tmp reg.
        // TODO: x64 supports index, base, const addressing, but other arches
        // don't

        // Offset is NOT a const, need additional offset + typed offset.
        auto offset_reg = ir_input_reg(t, regmap, ref_idx, 1);
        uint8_t addr_reg = RTMP2;
        if (ref->op1.constant) {
          // base_reg is already RTMP2 here; build address directly from const base.
          emit_mov64(s, addr_reg, slot_const(t, ref->op1));
          emit_add(s, addr_reg, addr_reg, offset_reg);
        } else {
          emit_mov(s, addr_reg, offset_reg);
          emit_add(s, addr_reg, addr_reg, base_reg);
        }
        emit_store(s, 8 - op->type, addr_reg, val_reg);
      }

      break;
    }
    case IR_REF: {
      break;
    }
    case IR_LT: {
      if (op->type == FLONUM_TAG) {
        // Side-exit on !(lhs < rhs): lhs >= rhs OR unordered.
        emit_flonum_cmp(s, t, op, arg0_reg, arg1_reg);
        emit_jcc32(s, JP, &t->snaps[cur_snap].patch_point);
        emit_jcc32(s, JAE, &t->snaps[cur_snap].patch_point);
      } else {
        emit_cmp_regs(s, t, arg0_reg, op->op2, arg1_reg);
        emit_jcc32(s, JGE, &t->snaps[cur_snap].patch_point);
      }
      break;
    }
    case IR_GT: {
      if (op->type == FLONUM_TAG) {
        // Side-exit on !(lhs > rhs): lhs <= rhs OR unordered.
        emit_flonum_cmp(s, t, op, arg0_reg, arg1_reg);
        emit_jcc32(s, JBE, &t->snaps[cur_snap].patch_point);
      } else {
        emit_cmp_regs(s, t, arg0_reg, op->op2, arg1_reg);
        emit_jcc32(s, JLE, &t->snaps[cur_snap].patch_point);
      }
      break;
    }
    case IR_GTE: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_cmp(s, t, op, arg0_reg, arg1_reg);
        // Side-exit on !(lhs >= rhs): lhs < rhs OR unordered.
        emit_jcc32(s, JP, &t->snaps[cur_snap].patch_point);
        emit_jcc32(s, JB, &t->snaps[cur_snap].patch_point);
      } else {
        emit_cmp_regs(s, t, arg0_reg, op->op2, arg1_reg);
        emit_jcc32(s, JL, &t->snaps[cur_snap].patch_point);
      }
      break;
    }
    case IR_LTE: {
      if (op->type == FLONUM_TAG) {
        // Side-exit on !(lhs <= rhs): lhs > rhs OR unordered.
        emit_flonum_cmp(s, t, op, arg0_reg, arg1_reg);
        emit_jcc32(s, JP, &t->snaps[cur_snap].patch_point);
        emit_jcc32(s, JA, &t->snaps[cur_snap].patch_point);
      } else {
        emit_cmp_regs(s, t, arg0_reg, op->op2, arg1_reg);
        emit_jcc32(s, JG, &t->snaps[cur_snap].patch_point);
      }
      break;
    }
    case IR_SUB: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_sub(s, t, dst_reg, op, arg0_reg, arg1_reg);
      } else {
        emit_arith_regs(s, t, dst_reg, arg0_reg, op->op2, arg1_reg, true);
        emit_typecheck(s, t, op, cur_snap, dst_reg);
      }
      break;
    }
    case IR_MUL: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_mul(s, t, dst_reg, op, arg0_reg, arg1_reg);
      } else {
        if (op->op2.constant) {
          int64_t rhs_untagged = slot_const(t, op->op2) / (1LL << FIXNUM_SHIFT);
          emit_mul_constant(s, dst_reg, arg0_reg, rhs_untagged);
        } else {
          // Keep tagged-fixnum semantics: untag one operand into RTMP.
          emit_sar_constant(s, RTMP, arg1_reg, FIXNUM_SHIFT);
          emit_mul(s, dst_reg, arg0_reg, RTMP);
        }
        emit_typecheck(s, t, op, cur_snap, dst_reg);
      }
      break;
    }
    case IR_DIV: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_div(s, t, dst_reg, op, arg0_reg, arg1_reg);
      } else {
        abort();
      }
      break;
    }
    case IR_QUOTIENT: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_quotient(s, t, dst_reg, op, arg0_reg, arg1_reg);
      } else {
        if (op->op2.constant) {
          emit_mov64(s, RTMP, slot_const(t, op->op2));
          emit_quotient(s, dst_reg, arg0_reg, RTMP);
        } else {
          emit_quotient(s, dst_reg, arg0_reg, arg1_reg);
        }
        emit_typecheck(s, t, op, cur_snap, dst_reg);
      }
      break;
    }
    case IR_MOD: {
      if (op->type == FLONUM_TAG) {
        abort();
      } else {
        if (op->op2.constant) {
          emit_mov64(s, RTMP, slot_const(t, op->op2));
          emit_mod(s, dst_reg, arg0_reg, RTMP);
        } else {
          emit_mod(s, dst_reg, arg0_reg, arg1_reg);
        }
        emit_typecheck(s, t, op, cur_snap, dst_reg);
      }
      break;
    }
    case IR_ADD: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_add(s, t, dst_reg, op, arg0_reg, arg1_reg);
      } else {
        // TODO: check for overflow
        emit_arith_regs(s, t, dst_reg, arg0_reg, op->op2, arg1_reg, false);
        emit_typecheck(s, t, op, cur_snap, dst_reg);
      }
      break;
    }
    case IR_INEXACT: {
      assert(op->type == FLONUM_TAG);
      assert(!op->op1.constant);
      assert(is_fpr_reg(dst_reg));
      emit_sar_constant(s, RTMP, arg0_reg, FIXNUM_SHIFT);
      emit_int64_to_double(s, dst_reg, RTMP);
      break;
    }
    case IR_EXACT: {
      assert(op->type == FIXNUM_TAG);
      assert(!op->op1.constant);
      assert(!is_fpr_reg(dst_reg));
      assert(is_fpr_reg(arg0_reg));
      emit_double_to_int64_trunc(s, RTMP, arg0_reg);
      emit_mul_constant(s, dst_reg, RTMP, (1LL << FIXNUM_SHIFT));
      break;
    }
    case IR_TRUNCATE: {
      assert(op->type == FLONUM_TAG);
      assert(!op->op1.constant);
      assert(is_fpr_reg(dst_reg));
      assert(is_fpr_reg(arg0_reg));
      emit_ftruncate(s, dst_reg, arg0_reg);
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
        emit_fmem_load(s, 8 - FLONUM_TAG, RTMP, dst_reg);
      } else {
        emit_mem_load(s, (int32_t)op->data * 8, RSTACK, dst_reg);
      }
      emit_typecheck(s, t, op, cur_snap, dst_reg);
      break;
    }
    case IR_GGET: {
      emit_mov64(s, RTMP, slot_const(t, op->op1) - SYMBOL_TAG);
      emit_mem_load(s, 16, RTMP, dst_reg);
      emit_typecheck(s, t, op, cur_snap, dst_reg);
      break;
    }
    case IR_GSET: {
      emit_mov64(s, RTMP, slot_const(t, op->op1) - SYMBOL_TAG);
      uint8_t val_reg = arg1_reg;
      if (op->op2.constant) {
        val_reg = RTMP2;
        emit_mov64(s, val_reg, slot_const(t, op->op2));
      } else {
        assert(val_reg != REG_NONE);
      }
      emit_store(s, 16, RTMP, val_reg);
      break;
    }
    case IR_RET: {
      // Compare return address on stack to expected target.
      assert(arg0_reg != REG_NONE);
      emit_mem_load(s, -8, RSTACK, arg0_reg);
      emit_cmp_constant(s, arg0_reg, slot_const(t, op->op2));
      emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
      emit_sub_constant(s, RSTACK, RSTACK, slot_const(t, op->op1));

      break;
    }
    case IR_ALLOC: {
      assert(op->op2.constant);
      bool dynamic_alloc = !op->op1.constant;
      uint64_t type_val = (uint64_t)(slot_const(t, op->op2) >> FIXNUM_SHIFT);
      uint8_t tag_bits = (uint8_t)(type_val & TAG_MASK);
      assert(s->alloc_slowpath);

      uint8_t save_regs[3];
      size_t save_cnt = 0;
      bool preserve_ret = dst_reg != RET_REG;
      bool preserve_ret2 = dst_reg != RET_REG2;
      bool preserve_rtmp2 =
          dynamic_alloc && !asm_rtmp2_reserved() && dst_reg != RTMP2;
      if (preserve_rtmp2) {
        save_regs[save_cnt++] = RTMP2;
      }
      if (preserve_ret2) {
        save_regs[save_cnt++] = RET_REG2;
      }
      if (preserve_ret) {
        // Keep caller's RET_REG live if allocation result goes elsewhere.
        save_regs[save_cnt++] = RET_REG;
      }
      emit_push_regs(s, save_regs, save_cnt, false);

      if (op->op1.constant) {
        int64_t tagged_size = slot_const(t, op->op1);
        int64_t size_bytes = tagged_size >> FIXNUM_SHIFT;
        assert((size_bytes & 7) == 0);
        uint64_t size_class = (uint64_t)size_bytes / 8;
        if (size_class < size_classes) {
          freelist_s *alloc_freelist = &freelist[size_class];
          label fastpath = {};
          label slow_cont = {};

          // Fastpath: inline gc_alloc for known size class.
          emit_mov64(s, RTMP, (intptr_t)alloc_freelist);
          emit_mem_load(s, freelist_start_offset, RTMP, RET_REG);
          emit_mem_load(s, freelist_end_offset, RTMP, RET_REG2);
          emit_mov(s, RTMP, RET_REG);
          emit_add_constant(s, RTMP, RTMP, size_bytes);
          emit_cmp(s, RTMP, RET_REG2);
          emit_jcc32(s, JLE, &fastpath);

          // Slowpath: call shared stub with tagged size.
          emit_mov64(s, RET_REG, tagged_size);
          emit_call32(s, (int64_t)s->alloc_slowpath);
          emit_jmp32(s, &slow_cont);

          emit_label(s, &fastpath);
          // Update freelist start_ptr to new head.
          emit_mov(s, RET_REG2, RTMP);
          emit_mov64(s, RTMP, (intptr_t)alloc_freelist);
          emit_store(s, freelist_start_offset, RTMP, RET_REG2);
          emit_label(s, &slow_cont);
        } else {
          // Large objects still go through the slowpath.
          emit_mov64(s, RET_REG, tagged_size);
          emit_call32(s, (int64_t)s->alloc_slowpath);
        }
      } else {
        // Dynamic size fastpath:
        //   size_class = tagged_size >> (FIXNUM_SHIFT + 3)
        //   if in range, probe freelist[size_class] inline
        //   otherwise call slowpath.
        label dyn_fastpath = {};
        label dyn_fast_commit = {};
        label dyn_slowpath = {};
        label dyn_cont = {};

        assert(arg0_reg != REG_NONE);

        COMMENT("  Alloc with dynamic size");
        // Preserve original tagged size across fastpath probing; RET_REG is reused.
        emit_mov(s, RTMP2, arg0_reg);
        emit_sar_constant(s, RET_REG2, RTMP2, FIXNUM_SHIFT + 3);
        emit_cmp_constant(s, RET_REG2, (int64_t)size_classes);
        emit_jcc32(s, JGE, &dyn_slowpath);

        COMMENT("  Fastpath small size");
        emit_label(s, &dyn_fastpath);
        emit_mul_constant(s, RET_REG2, RET_REG2, (int64_t)sizeof(freelist_s));
        emit_add_constant(s, RET_REG2, RET_REG2, (int64_t)(intptr_t)freelist);
        emit_mem_load(s, freelist_start_offset, RET_REG2, RET_REG);
        emit_mem_load(s, freelist_end_offset, RET_REG2, RET_REG2);

        // new_head = start_ptr + size_bytes, where size_bytes = tagged >> 3.
        emit_sar_constant(s, RTMP, RTMP2, FIXNUM_SHIFT);
        emit_add(s, RTMP, RET_REG, RTMP);
        emit_cmp(s, RTMP, RET_REG2);
        emit_jcc32(s, JLE, &dyn_fast_commit);

        COMMENT("  Slowpath (size too big or freelist empty)");
        emit_label(s, &dyn_slowpath);
        emit_mov(s, RET_REG, RTMP2);
        emit_call32(s, (int64_t)s->alloc_slowpath);
        emit_jmp32(s, &dyn_cont);

        // Fastpath success: store updated start_ptr.
        COMMENT("  Fastpath commit");
        emit_label(s, &dyn_fast_commit);
        // Recompute freelist base from preserved tagged size.
        emit_sar_constant(s, RET_REG2, RTMP2, FIXNUM_SHIFT + 3);
        emit_mul_constant(s, RET_REG2, RET_REG2, (int64_t)sizeof(freelist_s));
        // Avoid emit_add_constant here: large immediates use RTMP on x64, which
        // holds new_head for this fast-commit path.
        emit_mov64(s, RTMP2, (int64_t)(intptr_t)freelist);
        emit_add(s, RET_REG2, RET_REG2, RTMP2);
        emit_store(s, freelist_start_offset, RET_REG2, RTMP);
        emit_label(s, &dyn_cont);
      }

      COMMENT("  Alloc commit type");
      emit_store_constant(s, 0, RET_REG, (int64_t)type_val);
      emit_add_constant(s, dst_reg, RET_REG, tag_bits);

      emit_pop_regs(s, save_regs, save_cnt, false);
      break;
    }
    case IR_ARG:
    case IR_NOP:
    case IR_PMOV:
      break;
    case IR_TYPECHECK: {
      emit_typecheck(s, t, op, cur_snap, arg0_reg);
      if (out_reg == REG_NONE) {
      } else if (is_fpr_reg(out_reg)) {
        emit_unbox_flonum(s, arg0_reg, out_reg);
      } else {
        emit_mov(s, out_reg, arg0_reg);
      }
      break;
    }
    default: {
      printf("Can't jit op: %s\n", ir_names[op->op]);
      abort();
      // exit(-1);
    }
    }
    if (op->spill != SPILL_NONE && (op->op != IR_PMOV || op->reg != REG_NONE)) {
      assert(out_reg != REG_NONE);
      COMMENT("SPILL op %u to S%u", op_cnt_idx, op->spill);
      emit_mov64(s, RTMP, (intptr_t)spills);
      if (op->type == FLONUM_TAG) {
        emit_fstore(s, spill_offset(op->spill), RTMP, out_reg);
      } else {
        emit_store(s, spill_offset(op->spill), RTMP, out_reg);
      }
    }
    // TODO: maybe move emit_typecheck here, instead of each individual one.
    if (op->guard &&
        !(op->op == IR_ARG || op->op == IR_PMOV || op->op == IR_SLOAD ||
          op->op == IR_LOAD || op->op == IR_ALLOC || op->op == IR_TYPECHECK ||
          op->op == IR_SUB || op->op == IR_ADD || op->op == IR_MUL ||
          op->op == IR_DIV || op->op == IR_QUOTIENT ||
          op->op == IR_MOD || op->op == IR_GGET || op->op == IR_INEXACT ||
          op->op == IR_EXACT || op->op == IR_TRUNCATE)) {
      abort();
    }
  }
}

// Emit *two* entry points:
// One that loops back from the current trace
// One from c.
static void emit_root_trace_entry(emit_state *s, trace *t,
                                  regalloc2_result const *regmap) {
  // Emit an entry point from C.
  COMMENT("CENTRY");
  save_callee_regs(s);
  emit_mov(s, RSTATE, RARG0);
  emit_mov(s, RSTACK, RARG1);

  ir_ins *arg_ins = nullptr;
  for_each_leading_op(t, IR_ARG, arg_ins) {
    uint16_t ir_idx = (uint16_t)(arg_ins - t->ins);
    uint8_t out_reg = ir_output_reg(t, ir_idx);
    if (out_reg != REG_NONE) {
      auto offset = (int32_t)arg_ins->data * 8;
      if (is_fpr_reg(out_reg)) {
        emit_mem_load(s, offset, RSTACK, RTMP);
        emit_unbox_flonum(s, RTMP, out_reg);
      } else {
        emit_mem_load(s, offset, RSTACK, out_reg);
      }
    }
  }
}

static void emit_side_trace_entry(emit_state *s, trace *t,
                                  regalloc2_result const *regmap) {
  (void)regmap;
  // Install the side trace.
  uint8_t *patch_loc = t->parent_snap->patch_point.addr;
  asm_write_jmp32_at(s, patch_loc, (uint8_t *)emit_offset(s));
  __builtin___clear_cache((char *)patch_loc, (char *)patch_loc + 16);
}

trace_fn emit(trace *t, emit_state *s, record_state *record,
              uint8_t link_entry_snap) {
  // Initialize asm emitter memory if not already done (once per process)
  emit_init(s);

  // Allocate registers, print the IR in verbose mode.
  auto regmap = regalloc2(t);
  if (verbose) {
    print_ir(t, &regmap);
  }

  // Remember, we're emitting backwards! This makes the register
  // allocator much simpler to write, no state needs to be preserved.
  emit_writable_begin(s);

  // Emit a return-to-c stub.
  // TODO: could be shared by ALL traces
  auto start = emit_offset(s);

  if (!t->parent) {
    emit_root_trace_entry(s, t, &regmap);
  } else {
    emit_side_trace_entry(s, t, &regmap);
  }

  // This is where the trace will start when other traces are linked to it.
  // (without typechecking).
  emit_label(s, &t->trace_start);

  emit_ir(s, t, &regmap);

  // Link to the next trace: Which is either ourselves (if a looping parent
  // trace), or another trace (if a side trace).
  link_to_next_trace(s, t, &regmap, link_entry_snap);

  label exit_label = {};
  // Exist stubs for all but the loopback (last). These restore the scheme stack
  // state, putting any in-register values back on the stack, and boxing
  // flonums.
  emit_snapshot_exits(s, t, &regmap, t->snaps, &exit_label);

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
  arr_for_each(s->comments, entry) { free((void *)entry.text); }
  arrfree(s->comments);
  regalloc2_result_free(&regmap);

  // Install debuginfo for gdb & linux perf tool.
  char funcname[256];
  char *dumpname = t->parent ? "SIDE" : "TRACE";
  snprintf(funcname, sizeof(funcname), "%s_%i", dumpname, t->num);
  register_jit_symbol((uint8_t *)start, (uint8_t *)start, (uint8_t *)end,
                      funcname);
  // Call the built-in function to flush the cache for the specific range
  __builtin___clear_cache((char *)start, (char *)emit_offset(s));
  return (trace_fn)start;
}
