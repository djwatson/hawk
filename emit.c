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
#include "foreign.h"
#include "gc.h"
#include "hawk.h"
#include "ir.h"
#include "jitdump.h"
#include "parallel_copy.h"
#include "profiler.h"
#include "record.h"
#include "regalloc.h"
#include "runtime.h"
#include "vm.h"

static const int32_t flonum_payload_offset = (int32_t)offsetof(flonum_s, x);
static const int32_t symbol_val_offset = (int32_t)offsetof(symbol, val);

static inline uint8_t ref_base_tag(uint8_t type_tag) {
  return (uint8_t)((type_tag & TAG_MASK) == PTR_TAG ? PTR_TAG : type_tag);
}

static gc_obj gpr_spills[256];
static uint64_t fpr_spills[256];
enum : uint16_t { spill_slot_count = 256 };
static bool spill_roots_registered;

enum : int32_t {
  alloc_reg_save_stride = 8,
  alloc_stub_frame_size = MAX_REG * alloc_reg_save_stride,
};

static_assert((alloc_stub_frame_size & 15) == 0,
              "alloc slowpath frame must stay aligned");

static inline int32_t alloc_reg_save_slot_offset(uint8_t reg) {
  return reg * alloc_reg_save_stride;
}

static void *gc_alloc_ir_slowpath(uint64_t tagged_sz, uint8_t *reg_save,
                                  uint64_t gpr_mask) {
  for (uint8_t reg = 0; reg < FPR_REG_START; reg++) {
    if (gpr_mask & (1ULL << reg)) {
      gc_add_root((const void *)(reg_save + alloc_reg_save_slot_offset(reg)), 1,
                  0);
    }
  }

  void *ptr = gc_alloc((uint64_t)(tagged_sz >> FIXNUM_SHIFT));

  for (uint8_t reg = 0; reg < FPR_REG_START; reg++) {
    if (gpr_mask & (1ULL << reg)) {
      gc_remove_root((const void *)(reg_save + alloc_reg_save_slot_offset(reg)),
                     0);
    }
  }
  return ptr;
}

static void register_jit_symbol(uint8_t *start, uint8_t *entry, uint8_t *end,
                                const char *name) {
  profiler_register_jit_symbol(start, end, name);
  if (jit_dump_flag) {
    jit_reader_add((int)(end - entry), (uint64_t)entry, name);
    jit_dump((int)(end - start), (uint64_t)start, name);
    perf_map((uint64_t)start, (uint64_t)(end - start), name);
  }
}

static void emit_load_ralloc(emit_state *s) {
  emit_mov64(s, RTMP, (intptr_t)&gc_hp);
  emit_mem_load(s, 0, RTMP, RALLOC);
}

static void emit_store_ralloc(emit_state *s) {
  emit_mov64(s, RTMP, (intptr_t)&gc_hp);
  emit_store(s, 0, RTMP, RALLOC);
}

static void build_slowpath_reg_frame(uint8_t regs[FPR_REG_END],
                                     bool for_restore) {
  for (uint8_t reg = 0; reg < FPR_REG_END; reg++) {
    regs[reg] = reg;
  }
  regs[SP] = REG_NONE;
  if (for_restore) {
    regs[RTMP] = REG_NONE;
    regs[RTMP2] = REG_NONE;
  }
}

static void emit_save_slowpath_regs(emit_state *s) {
  uint8_t regs[FPR_REG_END];
  build_slowpath_reg_frame(regs, false);
  emit_push_regs(s, regs, FPR_REG_END, true);
}

static void emit_restore_slowpath_regs(emit_state *s) {
  uint8_t regs[FPR_REG_END];
  build_slowpath_reg_frame(regs, true);
  emit_pop_regs(s, regs, FPR_REG_END, true);
}

void emit_init_slowpath(emit_state *s) {
  if (s->alloc_slowpath) {
    return;
  }
  if (!spill_roots_registered) {
    gc_add_root((const void *)gpr_spills, spill_slot_count, 0);
    spill_roots_registered = true;
  }
  auto alloc_start = (uint8_t *)emit_offset(s);

  // Slowpath ABI: RTMP is tagged size, RTMP2 is live_gpr_mask.
  emit_writable_begin(s);

  emit_save_slowpath_regs(s);

  emit_mov(s, RARG0, RTMP);
  emit_mov(s, RARG1, SP);
  emit_mov(s, RARG2, RTMP2);
  emit_store_ralloc(s);
  emit_mov64(s, RTMP, (int64_t)&gc_alloc_ir_slowpath);
  emit_call_reg(s, RTMP);
  emit_mov(s, RTMP2, RET_REG);

  emit_restore_slowpath_regs(s);
  emit_load_ralloc(s); // clobbers RTMP
  emit_mov(s, RTMP, RTMP2);
  emit_ret(s);

  auto alloc_end = emit_offset(s);
  s->alloc_slowpath = alloc_start;

  emit_writable_end(s);
  register_jit_symbol(alloc_start, s->alloc_slowpath, (uint8_t *)alloc_end,
                      "GCslowpath");

  // Slowpath for expanding stack size.
  auto expand_start = (uint8_t *)emit_offset(s);

  emit_writable_begin(s);

  emit_save_slowpath_regs(s);
  emit_mov(s, RARG0, RSTATE);
  emit_mov(s, RARG1, RSTACK);
  emit_mov64(s, RTMP, (intptr_t)&expand_stack);
  emit_call_reg(s, RTMP);
  emit_mov(s, RTMP2, RET_REG);
  emit_restore_slowpath_regs(s);
  emit_mov(s, RSTACK, RTMP2);
  emit_ret(s);

  auto expand_end = emit_offset(s);
  s->expand_stack_slowpath = expand_start;

  emit_writable_end(s);
  register_jit_symbol(expand_start, s->expand_stack_slowpath,
                      (uint8_t *)expand_end, "ExpandStackSlowpath");
}

static inline bool ins_uses_freg(ir_ins const *ins) {
  return ins->type == FLONUM_TAG;
}

static inline bool is_fpr_reg(uint8_t reg) {
  return reg >= FPR_REG_START && reg != REG_NONE;
}
typedef struct {
  bool spilled;
  uint8_t reg;
  uint8_t spill;
} value_loc;

static value_loc snap_entry_loc(trace const *t, uint16_t snap_idx,
                                size_t entry_idx);
static void emit_typecheck(emit_state *s, trace *t, ir_ins const *op,
                           int32_t cur_snap, uint8_t reg);
static const uint8_t PAR_MOVE_MARKER = UINT8_MAX;

static uint8_t resolve_tmp_reg(uint8_t peer) {
  if (peer != PAR_MOVE_MARKER && is_fpr_reg(peer)) {
    return FRTMP;
  }
  return RTMP;
}

static inline ir_ins *slot_ins(trace *t, slot v) {
  assert(!v.constant);
  return &t->ins[v.loc];
}

static inline int64_t slot_const(trace *t, slot v) {
  assert(v.constant);
  return t->consts[v.loc].value;
}

static inline gc_obj slot_gc_obj(trace *t, slot v) {
  assert(v.constant);
  return t->consts[v.loc];
}

static void emit_heap_constant(emit_state *s, trace *t, uint8_t reg,
                               gc_obj value) {
  if (is_heap_object(value)) {
    arrput(t->gc_const_locs, asm_emit_mov64_patchable(s, reg, value.value));
    return;
  }
  emit_mov64(s, reg, value.value);
}

static inline int32_t spill_offset(uint8_t spill) {
  assert(spill != SPILL_NONE);
  return (int32_t)spill * 8;
}

static inline intptr_t spill_base(uint8_t type) {
  return (intptr_t)(type == FLONUM_TAG ? (void *)fpr_spills
                                       : (void *)gpr_spills);
}

static bool slot_is_zero(trace *t, slot s) {
  return s.constant && is_fixnum(t->consts[s.loc]) &&
         to_fixnum(t->consts[s.loc]) == 0;
}

static void mark_live_reg(bool live_regs[MAX_REG], uint64_t *live_gpr_mask,
                          uint8_t reg) {
  if (reg == REG_NONE || live_regs[reg]) {
    return;
  }
  live_regs[reg] = true;
  if (!is_fpr_reg(reg)) {
    *live_gpr_mask |= 1ULL << reg;
  }
}

// Collect roots live for one IR point (snap_idx < 0) or one snapshot.
static void collect_live_roots(trace *t, regalloc_state *ra_state,
                               uint16_t op_cnt_idx, int32_t snap_idx,
                               bool live_regs[MAX_REG],
                               uint64_t *live_gpr_mask) {
  memset(live_regs, 0, sizeof(bool) * MAX_REG);
  *live_gpr_mask = 0;

  if (snap_idx >= 0) {
    auto snap = &t->snaps[snap_idx];
    arr_for_each_idx(snap->slots, i) {
      auto entry = &snap->slots[i];
      if (entry->val.constant) {
        continue;
      }
      auto loc = snap_entry_loc(t, (uint16_t)snap_idx, i);
      if (loc.spilled) {
        continue;
      }
      mark_live_reg(live_regs, live_gpr_mask, loc.reg);
    }
    return;
  }

  size_t ins_len = arrlen(t->ins);
  for (uint8_t reg = 0; reg < MAX_REG; reg++) {
    uint16_t value_id = ra_state->regs[reg];
    if (value_id >= ins_len || value_id == op_cnt_idx ||
        !ra_state->uses[value_id]) {
      continue;
    }
    mark_live_reg(live_regs, live_gpr_mask, reg);
  }
}

static void emit_rooted_alloc(emit_state *s, uint64_t live_gpr_mask,
                              int64_t tagged_size, uint8_t size_reg) {
  label alloc_done = {};
  if (size_reg == REG_NONE) {
    emit_sub_constant(s, RALLOC, RALLOC, tagged_size >> FIXNUM_SHIFT);
  } else {
    emit_sar_constant(s, RTMP2, size_reg, FIXNUM_SHIFT);
    emit_sub(s, RALLOC, RALLOC, RTMP2);
  }

  emit_mov(s, RTMP, RALLOC);
  emit_mov64(s, RTMP2, (intptr_t)&gc_limit);
  emit_mem_load(s, 0, RTMP2, RTMP2);
  emit_cmp(s, RALLOC, RTMP2);
  emit_jcc32(s, JAE, &alloc_done);

  if (size_reg == REG_NONE) {
    emit_mov64(s, RTMP, tagged_size);
  } else {
    emit_mov(s, RTMP, size_reg);
  }
  emit_mov64(s, RTMP2, (int64_t)live_gpr_mask);

  emit_call32(s, (int64_t)s->alloc_slowpath);
  emit_label(s, &alloc_done);
}

static value_loc snap_entry_loc(trace const *t, uint16_t snap_idx,
                                size_t entry_idx) {
  auto sn = &t->snaps[snap_idx];
  auto entry = &sn->slots[entry_idx];
  assert(!entry->val.constant);
  auto ins = &t->ins[entry->val.loc];
  if (ins->spill != SPILL_NONE) {
    return (value_loc){.spilled = true, .reg = REG_NONE, .spill = ins->spill};
  }
  assert(ins->reg != REG_NONE);
  return (value_loc){.spilled = false, .reg = ins->reg, .spill = SPILL_NONE};
}

static uint8_t ir_output_reg(trace const *t, uint16_t ir_idx) {
  return t->ins[ir_idx].reg;
}

static inline uint8_t emit_arg_reg(slot *args, uint8_t *arg_regs,
                                   uint8_t arg_count, slot target);
static double slot_flonum_constant(trace *t, slot v);

typedef struct {
  slot value;
  foreign_type type;
} ccall_arg;

static uint8_t emit_collect_ccall_args(trace *t, slot chain,
                                       foreign_sig const *sig,
                                       ccall_arg *args) {
  uint8_t count = 0;
  while (!slot_is_zero(t, chain)) {
    if (count >= sig->argcnt || chain.constant) {
      abort();
    }
    auto carg = &t->ins[chain.loc];
    if (carg->op != IR_CARG) {
      abort();
    }
    args[count] =
        (ccall_arg){.value = carg->op1, .type = sig->arg_types[count]};
    chain = carg->op2;
    count++;
  }
  if (count != sig->argcnt) {
    abort();
  }
  return count;
}

static size_t collect_live_caller_saved_regs(trace *t, regalloc_state *ra_state,
                                             uint16_t op_cnt_idx,
                                             uint8_t *regs) {
  bool live_regs[MAX_REG];
  uint64_t live_gpr_mask;
  collect_live_roots(t, ra_state, op_cnt_idx, -1, live_regs, &live_gpr_mask);
  size_t count = 0;
  for (uint8_t reg = 0; reg < FPR_REG_END; reg++) {
    if (live_regs[reg] && !asm_is_callee_saved(reg)) {
      regs[count++] = reg;
    }
  }
  return count;
}

static void invalidate_live_regs_for_call(trace *t, regalloc_state *ra_state,
                                          uint8_t dst_reg) {
  enum : uint16_t {
    ALLOC_NONE_LOCAL = UINT16_MAX,
    ALLOC_UNALLOCATABLE_LOCAL = UINT16_MAX - 1,
  };
  size_t ins_len = arrlen(t->ins);
  for (size_t i = 0; i < MAX_REG; i++) {
    uint8_t reg = (uint8_t)i;
    if (reg == dst_reg) {
      continue;
    }
    uint16_t value_id = ra_state->regs[reg];
    if (value_id == ALLOC_UNALLOCATABLE_LOCAL) {
      continue;
    }
    if (value_id == ALLOC_NONE_LOCAL) {
      continue;
    }
    if (value_id >= ins_len) {
      continue;
    }
    ra_state->regs[reg] = ALLOC_NONE_LOCAL;
  }
}

static void emit_ccall_arg_value(emit_state *s, trace *t, ccall_arg const *arg,
                                 uint8_t src_reg, uint8_t dst_reg) {
  switch (arg->type) {
  case FOREIGN_TYPE_DOUBLE:
    if (arg->value.constant) {
      emit_fmov_constant(s, dst_reg, slot_flonum_constant(t, arg->value));
    } else {
      emit_fmov(s, dst_reg, src_reg);
    }
    return;
  case FOREIGN_TYPE_STRING: {
    int64_t str_offset = (int64_t)offsetof(string_s, str) - PTR_TAG;
    if (arg->value.constant) {
      emit_heap_constant(s, t, dst_reg, slot_gc_obj(t, arg->value));
      emit_add_constant(s, dst_reg, dst_reg, str_offset);
    } else {
      emit_add_constant(s, dst_reg, src_reg, str_offset);
    }
    return;
  }
  case FOREIGN_TYPE_UINT8:
  case FOREIGN_TYPE_INT32:
  case FOREIGN_TYPE_INT64:
  case FOREIGN_TYPE_UINT64:
    if (arg->value.constant) {
      emit_mov64(s, dst_reg, to_fixnum(slot_gc_obj(t, arg->value)));
    } else {
      emit_sar_constant(s, dst_reg, src_reg, FIXNUM_SHIFT);
    }
    return;
  case FOREIGN_TYPE_GC_OBJ:
    if (arg->value.constant) {
      emit_heap_constant(s, t, dst_reg, slot_gc_obj(t, arg->value));
    } else if (src_reg != dst_reg) {
      emit_mov(s, dst_reg, src_reg);
    }
    return;
  default:
    abort();
  }
}

static void emit_ccall_result(emit_state *s, uint8_t dst_reg,
                              foreign_type type) {
  switch (type) {
  case FOREIGN_TYPE_DOUBLE:
    if (dst_reg != asm_foreign_call_ret_fpr()) {
      emit_fmov(s, dst_reg, asm_foreign_call_ret_fpr());
    }
    return;
  case FOREIGN_TYPE_UINT8:
    emit_and_constant(s, dst_reg, RET_REG, 0xff);
    emit_shl_constant(s, dst_reg, dst_reg, FIXNUM_SHIFT);
    return;
  case FOREIGN_TYPE_INT32:
    emit_shl_constant(s, dst_reg, RET_REG, 32);
    emit_sar_constant(s, dst_reg, dst_reg, 32);
    emit_shl_constant(s, dst_reg, dst_reg, FIXNUM_SHIFT);
    return;
  case FOREIGN_TYPE_INT64:
  case FOREIGN_TYPE_UINT64:
    if (dst_reg != RET_REG) {
      emit_mov(s, dst_reg, RET_REG);
    }
    emit_shl_constant(s, dst_reg, dst_reg, FIXNUM_SHIFT);
    return;
  case FOREIGN_TYPE_GC_OBJ:
    if (dst_reg != RET_REG) {
      emit_mov(s, dst_reg, RET_REG);
    }
    return;
  default:
    abort();
  }
}

static void emit_gcobj_arg(emit_state *s, trace *t, slot value, uint8_t src_reg,
                           uint8_t dst_reg) {
  if (value.constant) {
    emit_heap_constant(s, t, dst_reg, slot_gc_obj(t, value));
    return;
  }
  if (src_reg != dst_reg) {
    emit_mov(s, dst_reg, src_reg);
  }
}

static void emit_move_pairs(emit_state *s, par_copy *cpy) {
  par_copy *moves = serialize_parallel_copy(cpy, PAR_MOVE_MARKER);
  arr_for_each_idx(moves, i) {
    auto mov = moves[i];
    uint64_t from_u64 = mov.from;
    uint64_t to_u64 = mov.to;
    uint8_t from = (uint8_t)from_u64;
    uint8_t to = (uint8_t)to_u64;
    if (from_u64 == PAR_MOVE_MARKER) {
      from = resolve_tmp_reg(to);
    }
    if (to_u64 == PAR_MOVE_MARKER) {
      to = resolve_tmp_reg(from);
      if (is_fpr_reg(from)) {
        emit_fmov(s, to, from);
      } else {
        emit_mov(s, to, from);
      }
      continue;
    }
    if (is_fpr_reg(from) != is_fpr_reg(to)) {
      abort();
    }
    if (is_fpr_reg(from)) {
      emit_fmov(s, to, from);
    } else {
      emit_mov(s, to, from);
    }
  }
  arrfree(cpy);
  arrfree(moves);
}

static void emit_ccall(emit_state *s, trace *t, regalloc_state *ra_state,
                       uint16_t op_cnt_idx, ir_ins const *op, slot *args,
                       uint8_t *arg_regs, uint8_t arg_count, uint8_t dst_reg) {
  foreign_sig sig;
  foreign_parse_sig(slot_gc_obj(t, op->op1), &sig);
  ccall_arg call_args[UINT8_MAX];
  uint8_t call_arg_count = emit_collect_ccall_args(t, op->op2, &sig, call_args);
  uint8_t save_regs[FPR_REG_END];
  size_t save_count =
      collect_live_caller_saved_regs(t, ra_state, op_cnt_idx, save_regs);
  emit_push_regs(s, save_regs, save_count, true);

  typedef struct {
    ccall_arg arg;
    uint8_t src_reg;
    uint8_t dst_reg;
  } pending_ccall_arg;

  pending_ccall_arg pending[UINT8_MAX] = {0};
  par_copy *cpy = nullptr;
  uint8_t next_gpr = 0;
  uint8_t next_fpr = 0;
  for (uint8_t i = 0; i < call_arg_count; i++) {
    auto *arg = &call_args[i];
    uint8_t src_reg = emit_arg_reg(args, arg_regs, arg_count, arg->value);
    if (!arg->value.constant && src_reg == REG_NONE) {
      abort();
    }
    uint8_t dst = arg->type == FOREIGN_TYPE_DOUBLE
                      ? asm_foreign_call_arg_fpr(next_fpr++)
                      : asm_foreign_call_arg_gpr(next_gpr++);
    pending[i] =
        (pending_ccall_arg){.arg = *arg, .src_reg = src_reg, .dst_reg = dst};
    if (!arg->value.constant) {
      arrput(cpy, ((par_copy){.from = src_reg, .to = dst}));
    }
  }
  if (next_gpr > asm_foreign_call_max_gpr_args() ||
      next_fpr > asm_foreign_call_max_fpr_args()) {
    abort();
  }

  emit_move_pairs(s, cpy);

  for (uint8_t i = 0; i < call_arg_count; i++) {
    auto *arg = &pending[i];
    if (arg->arg.value.constant) {
      emit_ccall_arg_value(s, t, &arg->arg, REG_NONE, arg->dst_reg);
    } else {
      emit_ccall_arg_value(s, t, &arg->arg, arg->dst_reg, arg->dst_reg);
    }
  }

  emit_store_ralloc(s);
  emit_mov64(s, RTMP, (intptr_t)sig.sym);
  emit_call_reg(s, RTMP);
  if (sig.ret_type == FOREIGN_TYPE_STRING) {
    if (RARG0 != RET_REG) {
      emit_mov(s, RARG0, RET_REG);
    }
    emit_mov64(s, RTMP, (intptr_t)&foreign_owned_string);
    emit_call_reg(s, RTMP);
    if (dst_reg != RET_REG) {
      emit_mov(s, dst_reg, RET_REG);
    }
  } else {
    emit_ccall_result(s, dst_reg, sig.ret_type);
  }
  emit_load_ralloc(s);
  invalidate_live_regs_for_call(t, ra_state, dst_reg);
  emit_pop_regs(s, save_regs, save_count, true);
}

static intptr_t vm_call_target(ir_ins_op op) {
  switch (op) {
  case IR_VMADD:
    return (intptr_t)&vm_runtime_math_add_slow;
  case IR_VMSUB:
    return (intptr_t)&vm_runtime_math_sub_slow;
  case IR_VMMUL:
    return (intptr_t)&vm_runtime_math_mul_slow;
  case IR_VMDIV:
    return (intptr_t)&vm_runtime_math_div_slow;
  case IR_VMQUOTIENT:
    return (intptr_t)&vm_runtime_math_quotient_slow;
  case IR_VMMOD:
    return (intptr_t)&vm_runtime_math_mod_slow;
  case IR_VMLT:
    return (intptr_t)&vm_runtime_cmp_lt_slow;
  case IR_VMGT:
    return (intptr_t)&vm_runtime_cmp_gt_slow;
  case IR_VMLTE:
    return (intptr_t)&vm_runtime_cmp_lte_slow;
  case IR_VMGTE:
    return (intptr_t)&vm_runtime_cmp_gte_slow;
  case IR_VMJEQV:
  case IR_VMJNEQV:
    return (intptr_t)&vm_runtime_cmp_jeqv_slow;
  case IR_VMINEXACT:
    return (intptr_t)&numeric_inexact_value;
  case IR_VMEXACT:
    return (intptr_t)&numeric_exact_value;
  case IR_VMTRUNCATE:
    return (intptr_t)&numeric_truncate_value;
  default:
    abort();
  }
}

static bool vm_call_is_cmp(ir_ins_op op) {
  switch (op) {
  case IR_VMLT:
  case IR_VMGT:
  case IR_VMLTE:
  case IR_VMGTE:
  case IR_VMJEQV:
  case IR_VMJNEQV:
    return true;
  default:
    return false;
  }
}

static bool vm_call_expects_false(ir_ins_op op) { return op == IR_VMJNEQV; }

static void emit_callcc(emit_state *s, trace *t, regalloc_state *ra_state,
                        uint16_t op_cnt_idx, ir_ins const *op, slot *args,
                        uint8_t *arg_regs, uint8_t arg_count, uint8_t dst_reg) {
  slot callcc_arg = op->op1;
  uint8_t arg_src = emit_arg_reg(args, arg_regs, arg_count, callcc_arg);
  if (!callcc_arg.constant && arg_src == REG_NONE) {
    abort();
  }

  emit_mov(s, RARG1, RSTACK);
  if (!callcc_arg.constant && arg_src != RARG2) {
    emit_mov(s, RARG2, arg_src);
  }
  emit_mov(s, RARG0, RSTATE);
  emit_gcobj_arg(s, t, callcc_arg, RARG2, RARG2);

  emit_store_ralloc(s);
  emit_mov64(s, RTMP, (intptr_t)&vm_callcc_slow);
  emit_call_reg(s, RTMP);
  emit_load_ralloc(s);
  // IR_CALLCC is treated as a VM call by regalloc, so any live values after
  // this point already have spill slots. Do not preserve caller-saved regs on
  // the host stack here: vm_callcc_slow may GC, which would leave those saved
  // copies stale while the spill/VM stack roots are updated.
  // vm_callcc_slow returns the callee frame, but the recorder resets
  // stack_off to 2 and keeps subsequent stack slots relative to stack_bottom.
  emit_sub_constant(s, RSTACK, RET_REG2, (int64_t)(sizeof(gc_obj) * 2));

  if (dst_reg != RET_REG && dst_reg != REG_NONE) {
    emit_mov(s, dst_reg, RET_REG);
  }
  invalidate_live_regs_for_call(t, ra_state, dst_reg);
}

static void emit_callcc_resume(emit_state *s, trace *t,
                               regalloc_state *ra_state, uint16_t op_cnt_idx,
                               ir_ins const *op, slot *args, uint8_t *arg_regs,
                               uint8_t arg_count) {
  (void)op_cnt_idx;
  slot captured = op->op1;
  uint8_t captured_src = emit_arg_reg(args, arg_regs, arg_count, captured);
  if (!captured.constant && captured_src == REG_NONE) {
    abort();
  }

  if (!captured.constant) {
    emit_mov(s, RARG1, captured_src);
  }
  emit_mov(s, RARG0, RSTATE);
  emit_gcobj_arg(s, t, captured, RARG1, RARG1);

  emit_mov64(s, RTMP, (intptr_t)&vm_callcc_resume_slow);
  emit_call_reg(s, RTMP);
  emit_mov(s, RSTACK, RET_REG);
  invalidate_live_regs_for_call(t, ra_state, REG_NONE);
}

static void emit_vmcall(emit_state *s, trace *t, regalloc_state *ra_state,
                        uint16_t op_cnt_idx, ir_ins const *op, slot *args,
                        uint8_t *arg_regs, uint8_t arg_count, uint8_t dst_reg,
                        int32_t cur_snap) {
  uint8_t save_regs[FPR_REG_END];
  size_t save_count =
      collect_live_caller_saved_regs(t, ra_state, op_cnt_idx, save_regs);
  emit_push_regs(s, save_regs, save_count, true);

  slot a0 = op->op1;
  uint8_t a0_src = emit_arg_reg(args, arg_regs, arg_count, a0);
  if (!a0.constant && a0_src == REG_NONE) {
    abort();
  }
  bool unary = (op->op == IR_VMINEXACT || op->op == IR_VMEXACT ||
                op->op == IR_VMTRUNCATE);
  slot a1 = op->op2;
  uint8_t a1_src = REG_NONE;
  if (!unary) {
    a1_src = emit_arg_reg(args, arg_regs, arg_count, a1);
    if (!a1.constant && a1_src == REG_NONE) {
      abort();
    }
  }

  par_copy *cpy = nullptr;
  if (!a0.constant) {
    arrput(cpy, ((par_copy){.from = a0_src, .to = RARG0}));
  }
  if (!unary && !a1.constant) {
    arrput(cpy, ((par_copy){.from = a1_src, .to = RARG1}));
  }
  emit_move_pairs(s, cpy);
  emit_gcobj_arg(s, t, a0, RARG0, RARG0);
  if (!unary) {
    emit_gcobj_arg(s, t, a1, RARG1, RARG1);
  }

  emit_store_ralloc(s);
  emit_mov64(s, RTMP, vm_call_target(op->op));
  emit_call_reg(s, RTMP);
  emit_load_ralloc(s);

  if (vm_call_is_cmp(op->op)) {
    assert(cur_snap >= 0);
    // Restore caller-saved regs before branching, but preserve VM compare
    // result in a scratch reg so stack pointer fixups cannot affect cmp/jcc.
    emit_mov(s, RTMP, RET_REG);
    emit_pop_regs(s, save_regs, save_count, true);
    emit_cmp_constant(s, RTMP, FALSE_REP.value);
    emit_jcc32(s, vm_call_expects_false(op->op) ? JNE : JE,
               &t->snaps[cur_snap].patch_point);
  } else {
    uint8_t out_reg = RET_REG;
    if (dst_reg != RET_REG && dst_reg != REG_NONE) {
      emit_mov(s, dst_reg, RET_REG);
      out_reg = dst_reg;
    } else if (dst_reg != REG_NONE) {
      out_reg = dst_reg;
    }
    emit_pop_regs(s, save_regs, save_count, true);
    if (cur_snap >= 0) {
      emit_typecheck(s, t, op, cur_snap, out_reg);
    }
  }
  invalidate_live_regs_for_call(t, ra_state, dst_reg);
}

static void emit_cmp_regs(emit_state *s, trace *t, uint8_t lhs_reg, slot rhs,
                          uint8_t rhs_reg) {
  assert(lhs_reg != REG_NONE);
  if (rhs.constant) {
    if (is_heap_object(slot_gc_obj(t, rhs))) {
      uint8_t cmp_reg = rhs_reg != REG_NONE ? rhs_reg : RTMP;
      emit_heap_constant(s, t, cmp_reg, slot_gc_obj(t, rhs));
      emit_cmp(s, lhs_reg, cmp_reg);
      return;
    }
    emit_cmp_constant(s, lhs_reg, slot_const(t, rhs));
    return;
  }
  assert(rhs_reg != REG_NONE);
  emit_cmp(s, lhs_reg, rhs_reg);
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

#define COMMENT(...) comment_append(emit_offset(s), &s->comments, __VA_ARGS__)

typedef struct {
  uint16_t slot;
  uint8_t target_reg;
} load_entry;

typedef struct {
  uint8_t target_reg;
  int64_t constant_value;
} const_entry;

typedef enum : uint8_t {
  LINK_MOVE,
  LINK_CONST,
  LINK_LOAD,
} link_action_kind;

typedef struct {
  link_action_kind kind;
  uint16_t exit_entry_idx;
  union {
    par_copy move;
    const_entry constant;
    load_entry load;
  };
} link_action;

// NOLINTBEGIN(clang-analyzer-core.NullDereference)
static void emit_stack_offset_and_check(emit_state *s, snap const *snap) {
  if (!snap->offset) {
    return;
  }

  COMMENT("Emit stack guard check");
  label done = {};
  emit_mem_load(s, (int32_t)offsetof(vm_state, stack_limit), RSTATE, RTMP);
  emit_cmp(s, RSTACK, RTMP);
  emit_jcc32(s, JL, &done);

  assert(s->expand_stack_slowpath);
  emit_call32(s, (int64_t)s->expand_stack_slowpath);

  emit_label(s, &done);
  COMMENT("   end stack guard check");

  // Advance stack pointer after confirming we have space.
  emit_add_constant(s, RSTACK, RSTACK, (int64_t)snap->offset * 8);
}

static double slot_flonum_constant(trace *t, slot v) {
  assert(v.constant);
  gc_obj obj = t->consts[v.loc];
  if (is_flonum(obj)) {
    return to_flonum(obj)->x;
  }
  abort();
}

static void emit_flonum_cmp(emit_state *s, trace *t, ir_ins const *op,
                            uint8_t lhs_reg, uint8_t rhs_reg) {
  assert(!op->op1.constant); // fold should have already removed these.
  if (op->op2.constant) {
    emit_fcmp_constant(s, lhs_reg, slot_flonum_constant(t, op->op2));
    return;
  }
  emit_fcmp(s, lhs_reg, rhs_reg);
}

static inline void emit_guard_cmp(emit_state *s, trace *t, ir_ins const *op,
                                  uint8_t lhs_reg, uint8_t rhs_reg,
                                  int32_t cur_snap, enum jcc_cond f_fail,
                                  enum jcc_cond i_fail) {
  if (op->type == FLONUM_TAG) {
    emit_flonum_cmp(s, t, op, lhs_reg, rhs_reg);
    emit_jcc32(s, f_fail, &t->snaps[cur_snap].patch_point);
    return;
  }

  emit_cmp_regs(s, t, lhs_reg, op->op2, rhs_reg);
  emit_jcc32(s, i_fail, &t->snaps[cur_snap].patch_point);
}

static inline void
emit_fixnum_binop_const(emit_state *s, trace *t, ir_ins const *op,
                        uint8_t dst_reg, uint8_t lhs_reg, uint8_t rhs_reg,
                        int32_t cur_snap, typeof(&emit_add) reg_emit,
                        typeof(&emit_add_constant) const_emit) {
  if (op->op2.constant) {
    const_emit(s, dst_reg, lhs_reg, slot_const(t, op->op2));
  } else {
    reg_emit(s, dst_reg, lhs_reg, rhs_reg);
  }
  emit_typecheck(s, t, op, cur_snap, dst_reg);
}

static void emit_flonum_binop(emit_state *s, trace *t, uint8_t dst, ir_ins *op,
                              typeof(&emit_fadd) binop, uint8_t lhs_reg,
                              uint8_t rhs_reg) {
  assert(is_fpr_reg(dst));
  assert(!op->op1.constant); // fold should have already removed these.
  if (op->op2.constant) {
    emit_fmov_constant(s, FRTMP, slot_flonum_constant(t, op->op2));
    binop(s, dst, lhs_reg, FRTMP);
    return;
  }
  binop(s, dst, lhs_reg, rhs_reg);
}

static void emit_box_flonum(emit_state *s, int32_t stack_offset,
                            uint8_t fpr_reg, bool store_to_stack,
                            bool live_regs[MAX_REG], uint64_t live_gpr_mask) {
  assert(is_fpr_reg(fpr_reg));

  live_regs[fpr_reg] = true;
  emit_rooted_alloc(s, live_gpr_mask, TAG_FIXNUM_VALUE(sizeof(flonum_s)),
                    REG_NONE);

  emit_store_constant(s, 0, RTMP, FLONUM_TAG);
  emit_fstore(s, flonum_payload_offset, RTMP, fpr_reg);
  emit_add_constant(s, RTMP, RTMP, FLONUM_TAG);

  // Do stuff with allocated space.
  if (store_to_stack) {
    emit_store(s, stack_offset, RSTACK, RTMP);
  }
  COMMENT("   end box flonum %s", reg_names[fpr_reg]);
}

static void emit_unbox_flonum(emit_state *s, uint8_t gpr_reg, uint8_t fpr_reg) {
  assert(!is_fpr_reg(gpr_reg));
  assert(is_fpr_reg(fpr_reg));
  emit_fmem_load(s, flonum_payload_offset - FLONUM_TAG, gpr_reg, fpr_reg);
}

static void emit_serialized_moves(emit_state *s, par_copy *cpy,
                                  bool live_regs[MAX_REG],
                                  uint64_t live_gpr_mask) {
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
        emit_box_flonum(s, 0, from, false, live_regs, live_gpr_mask);
        emit_mov(s, to, RTMP);
        mark_live_reg(live_regs, &live_gpr_mask, to);
      } else if (dst_fpr && !src_fpr) {
        COMMENT("Unbox flonum %s to %s", reg_names[from], reg_names[to]);
        emit_unbox_flonum(s, from, to);
      } else {
        assert(!"Unsupported register move");
      }
    } else {
      emit_mov(s, to, from);
      mark_live_reg(live_regs, &live_gpr_mask, to);
    }
  }
  arrfree(cpy);
  arrfree(moves);
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

    emit_mov64(s, RTMP, spill_base(ins->type));
    if (ins->type == FLONUM_TAG) {
      emit_fstore(s, spill_offset(ins->spill), RTMP, ins->reg);
    } else {
      emit_store(s, spill_offset(ins->spill), RTMP, ins->reg);
    }
  }
}

static void emit_typecheck(emit_state *s, trace *t, ir_ins const *op,
                           int32_t cur_snap, uint8_t reg) {
  if ((!op->guard && op->type != FLONUM_TAG) ||
      (op->type == FLONUM_TAG && is_fpr_reg(reg))) {
    return;
  }

  uint8_t low_tag = op->type & TAG_MASK;
  uint8_t tmp = reg == RTMP ? RTMP2 : RTMP;
  int64_t mask = TAG_MASK;
  int64_t want = op->type;
  COMMENT("  typecheck %s", low_tag_names[low_tag]);
  switch (low_tag) {
  case LITERAL_TAG:
    mask = IMMEDIATE_MASK;
    want &= IMMEDIATE_MASK;
    break;
  case FIXNUM_TAG:
    emit_test_constant(s, reg, TAG_MASK);
    emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
    return;
  case PTR_TAG:
    if (op->type == FUNC_TAG) {
      // func loads ONLY happen from closure loads, no need to typecheck.
      return;
    }
    emit_mov(s, tmp, reg);
    emit_and_constant(s, tmp, tmp, TAG_MASK);
    emit_cmp_constant(s, tmp, PTR_TAG);
    emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
    if (op->type == PTR_TAG) {
      return;
    }
    emit_mov(s, tmp, reg);
    emit_sub_constant(s, tmp, tmp, PTR_TAG);
    emit_mem_load(s, 0, tmp, tmp);
    emit_cmp_constant(s, tmp, op->type);
    emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
    return;
  default:
    break;
  }

  emit_mov(s, tmp, reg);
  emit_and_constant(s, tmp, tmp, mask);
  emit_cmp_constant(s, tmp, want);
  emit_jcc32(s, JNE, &t->snaps[cur_snap].patch_point);
}

static void collect_link_actions(trace *exit_trace, uint16_t exit_snap_idx,
                                 trace *entry_trace, uint16_t entry_snap_idx,
                                 link_action **actions_out) {
  link_action *actions = nullptr;
  auto exit_snap = &exit_trace->snaps[exit_snap_idx];
  auto entry_snap = &entry_trace->snaps[entry_snap_idx];
  size_t exit_len = arrlen(exit_snap->slots);
  size_t entry_len = arrlen(entry_snap->slots);
  size_t i = 0;
  size_t j = 0;
  while (i < exit_len && j < entry_len) {
    auto exit_entry = &exit_snap->slots[i];
    int32_t exit_logical =
        (int32_t)exit_entry->slot - (int32_t)exit_snap->offset;
    auto entry = &entry_snap->slots[j];
    uint16_t entry_slot = entry->slot;

    if (exit_logical == (int32_t)entry_slot) {
      value_loc exit_loc = {0};
      value_loc entry_loc = {0};
      uint8_t entry_reg = REG_NONE;
      if (!exit_entry->val.constant) {
        exit_loc = snap_entry_loc(exit_trace, exit_snap_idx, i);
      }
      if (!entry->val.constant) {
        entry_loc = snap_entry_loc(entry_trace, entry_snap_idx, j);
        entry_reg = entry_trace->ins[entry->val.loc].reg;
        if (entry_reg == REG_NONE && !entry_loc.spilled) {
          entry_reg = entry_loc.reg;
        }
      }

      if (exit_entry->val.constant && !entry->val.constant &&
          entry_reg != REG_NONE) {
        arrput(actions, ((link_action){
                            .kind = LINK_CONST,
                            .exit_entry_idx = (uint16_t)i,
                            .constant =
                                {
                                    .target_reg = entry_reg,
                                    .constant_value =
                                        slot_const(exit_trace, exit_entry->val),
                                },
                        }));
      } else if (!exit_entry->val.constant && !entry->val.constant &&
                 entry_reg != REG_NONE) {
        if (!exit_loc.spilled) {
          arrput(actions, ((link_action){
                              .kind = LINK_MOVE,
                              .exit_entry_idx = (uint16_t)i,
                              .move = {.from = exit_loc.reg, .to = entry_reg},
                          }));
        } else {
          arrput(actions,
                 ((link_action){
                     .kind = LINK_LOAD,
                     .exit_entry_idx = UINT16_MAX,
                     .load = {.slot = entry_slot, .target_reg = entry_reg},
                 }));
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
    if (!entry->val.constant) {
      uint8_t target_reg = entry_trace->ins[entry->val.loc].reg;
      if (target_reg != REG_NONE) {
        arrput(actions,
               ((link_action){
                   .kind = LINK_LOAD,
                   .exit_entry_idx = UINT16_MAX,
                   .load = {.slot = entry_slot, .target_reg = target_reg},
               }));
      }
    }
    j++;
  }

  // Remaining unmatched entry slots.
  while (j < entry_len) {
    auto entry = &entry_snap->slots[j];
    if (!entry->val.constant) {
      uint8_t target_reg = entry_trace->ins[entry->val.loc].reg;
      if (target_reg != REG_NONE) {
        arrput(actions,
               ((link_action){
                   .kind = LINK_LOAD,
                   .exit_entry_idx = UINT16_MAX,
                   .load = {.slot = entry->slot, .target_reg = target_reg},
               }));
      }
    }
    j++;
  }

  *actions_out = actions;
}

static void emit_snap_store_entry(emit_state *s, trace *t, uint16_t snap_idx,
                                  size_t entry_idx, snap_entry const *entry,
                                  bool live_regs[MAX_REG],
                                  uint64_t live_gpr_mask) {
  auto stack_offset = (int32_t)entry->slot * 8;
  if (entry->val.constant) {
    gc_obj value = slot_gc_obj(t, entry->val);
    if (is_heap_object(value)) {
      emit_heap_constant(s, t, RTMP, value);
      emit_store(s, stack_offset, RSTACK, RTMP);
    } else {
      emit_store_constant(s, stack_offset, RSTACK, value.value);
    }
    return;
  }

  auto ins = &t->ins[entry->val.loc];
  auto loc = snap_entry_loc(t, snap_idx, entry_idx);
  uint8_t val_reg = REG_NONE;
  if (loc.spilled) {
    emit_mov64(s, RTMP, spill_base(ins->type));
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
    emit_box_flonum(s, stack_offset, val_reg, true, live_regs, live_gpr_mask);
  } else {
    emit_store(s, stack_offset, RSTACK, val_reg);
  }
}

static void emit_snap(emit_state *s, trace *t, uint16_t snap_idx, bool exit) {
  auto snap = &t->snaps[snap_idx];
  bool live_regs[MAX_REG];
  uint64_t live_gpr_mask;
  collect_live_roots(t, nullptr, 0, snap_idx, live_regs, &live_gpr_mask);

  arr_for_each_idx(snap->slots, j) {
    emit_snap_store_entry(s, t, snap_idx, j, &snap->slots[j], live_regs,
                          live_gpr_mask);
  }

  emit_stack_offset_and_check(s, snap);
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
  emit_store_ralloc(s);
  restore_callee_regs(s);
  emit_ret(s);
}

static void emit_snapshot_exits(emit_state *s, trace *t, snap *snaps,
                                label *exit_label) {
  // There will always be at least two snapshots.  Don't write the last, it's
  // the loopback snap.
  for (uint64_t i = 0; i < arrlen(snaps) - 1; i++) {
    COMMENT("Snap exit #%i", i);
    snap *snap = &snaps[i];
    emit_label(s, &snap->patch_point);
    emit_snap(s, t, (uint16_t)i, true);
    emit_jmp32(s, exit_label);
  }
}

static void link_to_next_trace(emit_state *s, trace *t,
                               uint8_t entry_snap_idx) {
  auto cur_snap = (uint16_t)(arrlen(t->snaps) - 1);

  trace *linked_trace = t->link;

  if (linked_trace == t) {
    COMMENT("Loopback (snap exit %i)", cur_snap);
  } else {
    COMMENT("Link to trace %i (snap exit %i)", t->link->num, cur_snap);
  }

  link_action *actions = nullptr;
  bool live_regs[MAX_REG];
  uint64_t live_gpr_mask;
  collect_live_roots(t, nullptr, 0, cur_snap, live_regs, &live_gpr_mask);
  collect_link_actions(t, cur_snap, linked_trace, entry_snap_idx, &actions);
  auto snap = &t->snaps[cur_snap];
  arr_for_each_idx(snap->slots, j) {
    bool skip = false;
    arr_for_each_idx(actions, i) {
      if (actions[i].exit_entry_idx == j) {
        skip = true;
        break;
      }
    }
    if (!skip) {
      emit_snap_store_entry(s, t, cur_snap, j, &snap->slots[j], live_regs,
                            live_gpr_mask);
    }
  }
  emit_stack_offset_and_check(s, snap);

  // Execute reg->reg reconciliation before stack loads so load targets do not
  // clobber move sources from the exit state.
  par_copy *cpy = nullptr;
  arr_for_each_idx(actions, i) {
    auto action = &actions[i];
    if (action->kind == LINK_MOVE) {
      arrput(cpy, action->move);
    }
  }
  emit_serialized_moves(s, cpy, live_regs, live_gpr_mask);

  arr_for_each_idx(actions, i) {
    auto action = &actions[i];
    if (action->kind == LINK_LOAD) {
      assert(action->load.target_reg != REG_NONE);
      auto stack_off = (int32_t)action->load.slot * 8;
      if (is_fpr_reg(action->load.target_reg)) {
        emit_mem_load(s, stack_off, RSTACK, RTMP);
        emit_fmem_load(s, 8 - FLONUM_TAG, RTMP, action->load.target_reg);
      } else {
        emit_mem_load(s, stack_off, RSTACK, action->load.target_reg);
      }
    }
  }
  arr_for_each_idx(actions, i) {
    auto action = &actions[i];
    if (action->kind == LINK_CONST) {
      assert(action->constant.target_reg != REG_NONE);
      if (is_fpr_reg(action->constant.target_reg)) {
        emit_fmov_constant(
            s, action->constant.target_reg,
            to_flonum((gc_obj){.value = action->constant.constant_value})->x);
      } else {
        emit_heap_constant(s, t, action->constant.target_reg,
                           (gc_obj){.value = action->constant.constant_value});
      }
    }
  }
  emit_loopback_entry_spills(s, linked_trace, entry_snap_idx);
  arrfree(actions);

  label *target =
      entry_snap_idx == 1 ? &t->link->snap_entry_label : &t->link->trace_start;
  emit_jmp32(s, target);
}

static void emit_reload_arg(emit_state *s, trace *t, uint16_t value_id,
                            uint8_t reg) {
  auto in = &t->ins[value_id];
  emit_mov64(s, RTMP, spill_base(in->type));
  if (in->type == FLONUM_TAG) {
    emit_fmem_load(s, spill_offset(in->spill), RTMP, reg);
  } else {
    emit_mem_load(s, spill_offset(in->spill), RTMP, reg);
  }
}

static inline uint8_t emit_arg_reg(slot *args, uint8_t *arg_regs,
                                   uint8_t arg_count, slot target) {
  if (target.constant) {
    return REG_NONE;
  }
  for (uint8_t i = 0; i < arg_count; i++) {
    if (!args[i].constant && args[i].loc == target.loc) {
      return arg_regs[i];
    }
  }
  return REG_NONE;
}

static void emit_ir(emit_state *s, trace *t, regalloc_state *ra_state) {
  int32_t cur_snap = -1;
  size_t snap_idx = 0;
  uint16_t op_cnt_idx = 0;

  for (; op_cnt_idx < arrlen(t->ins); op_cnt_idx++) {
    while (snap_idx < arrlen(t->snaps) && t->snaps[snap_idx].ir == op_cnt_idx) {
      if (snap_idx == 1) {
        emit_label(s, &t->snap_entry_label);
      }
      if (snap_idx > 0) {
        regalloc_maybe_free_snapshot(ra_state, op_cnt_idx,
                                     &t->snaps[snap_idx - 1]);
      }
      cur_snap = (int32_t)snap_idx;
      snap_idx++;
    }
    auto op = &t->ins[op_cnt_idx];

    COMMENT("%i %s", op_cnt_idx, ir_names[op->op]);
    // Begin regalloc
    // TODO: cleanup arg0_reg etc
    slot args[UINT8_MAX];
    uint8_t arg_count = regalloc_collect_ir_args(t, op, args);
    uint8_t arg_regs[UINT8_MAX];
    memset(arg_regs, REG_NONE, sizeof(arg_regs));
    for (uint8_t arg = 0; arg < arg_count; arg++) {
      if (args[arg].constant) {
        continue;
      }
      uint8_t old_reg =
          regalloc_find_current_reg_for_value(ra_state, args[arg].loc);
      uint8_t arg_reg = regalloc_materialize_arg_or_ensure_loc(
          ra_state, (uint16_t)op_cnt_idx, op, args[arg].loc);
      arg_regs[arg] = arg_reg;
      if (old_reg == REG_NONE) {
        emit_reload_arg(s, t, args[arg].loc, arg_reg);
      }
    }
    for (uint8_t arg = 0; arg < arg_count; arg++) {
      if (!args[arg].constant) {
        regalloc_maybe_free_reg(ra_state, (uint16_t)op_cnt_idx, args[arg].loc,
                                false);
      }
    }

    regalloc_assign_output(ra_state, op_cnt_idx, op);
    uint8_t out_reg = op->reg;
    uint8_t dst_reg = out_reg;
    if (op->op == IR_RET && out_reg == REG_NONE) {
      dst_reg = regalloc_find_free_reg(ra_state, false, op);
    } else if (dst_reg == REG_NONE) {
      dst_reg = ins_uses_freg(op) ? FRTMP : RTMP;
    }
    uint8_t arg0_reg = arg_count > 0 ? arg_regs[0] : REG_NONE;
    uint8_t arg1_reg = arg_count > 1 ? arg_regs[1] : REG_NONE;
    if (op->op == IR_RET && arg0_reg == REG_NONE) {
      arg0_reg = dst_reg;
    } else {
      // no-op
    }
    // End regalloc

#define EMIT_CMP_CASE(opname, f_fail, i_fail)                                  \
  case opname: {                                                               \
    emit_guard_cmp(s, t, op, arg0_reg, arg1_reg, cur_snap, f_fail, i_fail);    \
    break;                                                                     \
  }
#define EMIT_GUARDED_ARITH_CASE(opname, float_emit, reg_emit, const_emit)      \
  case opname: {                                                               \
    if (op->type == FLONUM_TAG) {                                              \
      emit_flonum_binop(s, t, dst_reg, op, float_emit, arg0_reg, arg1_reg);    \
    } else if (op->op2.constant) {                                             \
      const_emit(s, dst_reg, arg0_reg, slot_const(t, op->op2),                 \
                 &t->snaps[cur_snap].patch_point);                             \
    } else {                                                                   \
      reg_emit(s, dst_reg, arg0_reg, arg1_reg,                                 \
               &t->snaps[cur_snap].patch_point);                               \
    }                                                                          \
    break;                                                                     \
  }
    switch (op->op) {
      EMIT_CMP_CASE(IR_EQ, JNE, JNE)
      EMIT_CMP_CASE(IR_NE, JE, JE)
    case IR_LOAD: {
      uint8_t base_reg = emit_arg_reg(args, arg_regs, arg_count, op->op1);
      uint8_t offset_reg = emit_arg_reg(args, arg_regs, arg_count, op->op2);
      if (op->op1.constant) {
        // Materialize constant base object pointer for direct loads.
        base_reg = RTMP;
        emit_heap_constant(s, t, base_reg, slot_gc_obj(t, op->op1));
      }
      uint8_t base_type = op->op1.constant ? get_tag(t->consts[op->op1.loc])
                                           : slot_ins(t, op->op1)->type;
      bool unknown_base = base_type == UNDEFINED_TAG;
      base_type = ref_base_tag(base_type);
      int32_t typed_offset = (int32_t)((int64_t)sizeof(gc_header) - base_type);
      if (op->type == FLONUM_TAG) {
        // Slot contains a tagged flonum gc_obj; load object first, then
        // payload. Prefer the dedicated secondary scratch register when
        // available.
        uint8_t obj_reg = RTMP2;
        if (unknown_base) {
          emit_and_constant(s, obj_reg, base_reg, ~(int64_t)TAG_MASK);
          if (op->op2.constant) {
            int64_t offset_bytes =
                t->consts[op->op2.loc].value + (int64_t)sizeof(gc_header);
            emit_mem_load(s, (int32_t)offset_bytes, obj_reg, obj_reg);
          } else {
            emit_add(s, obj_reg, offset_reg, obj_reg);
            emit_mem_load(s, (int32_t)sizeof(gc_header), obj_reg, obj_reg);
          }
        } else if (op->op2.constant) {
          int64_t offset_bytes = t->consts[op->op2.loc].value + typed_offset;
          emit_mem_load(s, (int32_t)offset_bytes, base_reg, obj_reg);
        } else {
          emit_add(s, obj_reg, offset_reg, base_reg);
          emit_mem_load(s, typed_offset, obj_reg, obj_reg);
        }
        emit_typecheck(s, t, op, cur_snap, obj_reg);
        emit_fmem_load(s, 8 - FLONUM_TAG, obj_reg, dst_reg);
      } else {
        if (unknown_base) {
          emit_and_constant(s, RTMP, base_reg, ~(int64_t)TAG_MASK);
          if (op->op2.constant) {
            int64_t offset_bytes =
                t->consts[op->op2.loc].value + (int64_t)sizeof(gc_header);
            emit_mem_load(s, (int32_t)offset_bytes, RTMP, dst_reg);
          } else {
            emit_add(s, RTMP, offset_reg, RTMP);
            emit_mem_load(s, (int32_t)sizeof(gc_header), RTMP, dst_reg);
          }
        } else if (op->op2.constant) {
          int64_t offset_bytes = t->consts[op->op2.loc].value + typed_offset;
          emit_mem_load(s, (int32_t)offset_bytes, base_reg, dst_reg);
        } else {
          emit_add(s, RTMP, offset_reg, base_reg);
          emit_mem_load(s, typed_offset, RTMP, dst_reg);
        }
        emit_typecheck(s, t, op, cur_snap, dst_reg);
      }
      break;
    }
    case IR_LOAD_CHAR: {
      uint8_t base_reg = emit_arg_reg(args, arg_regs, arg_count, op->op1);
      if (op->op1.constant) {
        base_reg = RTMP;
        emit_heap_constant(s, t, base_reg, slot_gc_obj(t, op->op1));
      }
      int32_t base_offset = (int32_t)offsetof(string_s, str) - PTR_TAG;
      if (op->op2.constant) {
        int64_t idx = slot_const(t, op->op2) >> FIXNUM_SHIFT;
        assert((int32_t)idx == idx);
        emit_mem_load_u8(s, (int32_t)idx + base_offset, base_reg, dst_reg);
      } else {
        uint8_t offset_reg = emit_arg_reg(args, arg_regs, arg_count, op->op2);
        emit_sar_constant(s, RTMP, offset_reg, FIXNUM_SHIFT);
        emit_add(s, RTMP, RTMP, base_reg);
        emit_mem_load_u8(s, base_offset, RTMP, dst_reg);
      }
      emit_shl_constant(s, dst_reg, dst_reg, 8);
      emit_add_constant(s, dst_reg, dst_reg, CHAR_TAG);
      break;
    }
    case IR_STORE: {
      ir_ins *ref = slot_ins(t, op->op1);
      auto val_reg = arg0_reg;
      if (op->op2.constant) {
        emit_heap_constant(s, t, RTMP, slot_gc_obj(t, op->op2));
        val_reg = RTMP;
      } else {
        val_reg = emit_arg_reg(args, arg_regs, arg_count, op->op2);
      }
      assert(val_reg != REG_NONE || op->op2.constant);
      if (is_fpr_reg(val_reg)) {
        bool live_regs[MAX_REG];
        uint64_t live_gpr_mask;
        collect_live_roots(t, ra_state, op_cnt_idx, -1, live_regs,
                           &live_gpr_mask);
        emit_box_flonum(s, 0, val_reg, false, live_regs, live_gpr_mask);
        val_reg = RTMP;
      }

      auto base_reg = emit_arg_reg(args, arg_regs, arg_count, ref->op1);
      if (ref->op1.constant) {
        // REF base can be a constant object (e.g. global vector).
        // Materialize it explicitly since constant args have no input reg.
        base_reg = RTMP2;
        emit_heap_constant(s, t, base_reg, slot_gc_obj(t, ref->op1));
      }
      if (ref->op2.constant) {
        // Offset is a constant.
        auto offset =
            slot_const(t, ref->op2) + (int64_t)(8 - ref_base_tag(op->type));
        assert((int32_t)offset == offset);
        emit_store(s, (int32_t)offset, base_reg, val_reg);
      } else {
        // We need a tmp reg.
        // TODO: x64 supports index, base, const addressing, but other arches
        // don't

        // Offset is NOT a const, need additional offset + typed offset.
        auto offset_reg = emit_arg_reg(args, arg_regs, arg_count, ref->op2);
        uint8_t addr_reg = RTMP2;
        if (ref->op1.constant) {
          // base_reg is already RTMP2 here; build address directly from const
          // base.
          emit_heap_constant(s, t, addr_reg, slot_gc_obj(t, ref->op1));
          emit_add(s, addr_reg, addr_reg, offset_reg);
        } else {
          emit_mov(s, addr_reg, offset_reg);
          emit_add(s, addr_reg, addr_reg, base_reg);
        }
        emit_store(s, 8 - ref_base_tag(op->type), addr_reg, val_reg);
      }

      break;
    }
    case IR_STORE_CHAR: {
      ir_ins *ref = slot_ins(t, op->op1);
      auto base_reg = emit_arg_reg(args, arg_regs, arg_count, ref->op1);
      if (ref->op1.constant) {
        base_reg = RTMP2;
        emit_heap_constant(s, t, base_reg, slot_gc_obj(t, ref->op1));
      }
      int32_t base_offset = (int32_t)offsetof(string_s, str) - PTR_TAG;
      int32_t store_offset = base_offset;
      if (ref->op2.constant) {
        int64_t idx = slot_const(t, ref->op2) >> FIXNUM_SHIFT;
        assert((int32_t)idx == idx);
        store_offset += (int32_t)idx;
      } else {
        auto offset_reg = emit_arg_reg(args, arg_regs, arg_count, ref->op2);
        uint8_t addr_reg = RTMP2;
        if (ref->op1.constant) {
          emit_sar_constant(s, RTMP, offset_reg, FIXNUM_SHIFT);
          emit_add(s, addr_reg, addr_reg, RTMP);
        } else {
          emit_sar_constant(s, addr_reg, offset_reg, FIXNUM_SHIFT);
          emit_add(s, addr_reg, addr_reg, base_reg);
        }
        base_reg = addr_reg;
      }

      if (op->op2.constant) {
        auto ch = (uint8_t)to_char(slot_gc_obj(t, op->op2));
        emit_mov64(s, RTMP, ch);
      } else {
        uint8_t val_reg = emit_arg_reg(args, arg_regs, arg_count, op->op2);
        emit_sar_constant(s, RTMP, val_reg, 8);
      }
      emit_store_u8(s, store_offset, base_reg, RTMP);
      break;
    }
      EMIT_CMP_CASE(IR_LT, JAE, JGE)
      EMIT_CMP_CASE(IR_GT, JBE, JLE)
      EMIT_CMP_CASE(IR_GTE, JB, JL)
      EMIT_CMP_CASE(IR_LTE, JA, JG)
    case IR_CONST: {
      assert(op->op1.constant);
      if (op->type == FLONUM_TAG) {
        emit_fmov_constant(s, dst_reg, slot_flonum_constant(t, op->op1));
      } else {
        emit_heap_constant(s, t, dst_reg, slot_gc_obj(t, op->op1));
      }
      break;
    }
      EMIT_GUARDED_ARITH_CASE(IR_SUB, emit_fsub,
                              asm_emit_fixnum_sub_guard_overflow,
                              asm_emit_fixnum_sub_constant_guard_overflow)
    case IR_MUL: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_binop(s, t, dst_reg, op, emit_fmul, arg0_reg, arg1_reg);
      } else {
        if (op->op2.constant) {
          int64_t rhs_untagged = slot_const(t, op->op2) / (1LL << FIXNUM_SHIFT);
          asm_emit_fixnum_mul_constant_guard_overflow(
              s, dst_reg, arg0_reg, rhs_untagged,
              &t->snaps[cur_snap].patch_point);
        } else {
          emit_sar_constant(s, RTMP, arg1_reg, FIXNUM_SHIFT);
          asm_emit_fixnum_mul_guard_overflow(s, dst_reg, arg0_reg, RTMP,
                                             &t->snaps[cur_snap].patch_point);
        }
      }
      break;
    }
    case IR_DIV: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_binop(s, t, dst_reg, op, emit_fdiv, arg0_reg, arg1_reg);
      } else {
        abort();
      }
      break;
    }
    case IR_QUOTIENT: {
      if (op->type == FLONUM_TAG) {
        emit_flonum_binop(s, t, dst_reg, op, emit_fdiv, arg0_reg, arg1_reg);
        emit_ftruncate(s, dst_reg, dst_reg);
      } else {
        emit_fixnum_binop_const(s, t, op, dst_reg, arg0_reg, arg1_reg, cur_snap,
                                emit_quotient, emit_quotient_constant);
      }
      break;
    }
    case IR_MOD: {
      if (op->type == FLONUM_TAG) {
        assert(!op->op1.constant);
        uint8_t rhs_reg = arg1_reg;
        if (op->op2.constant) {
          rhs_reg = FRTMP;
          emit_fmov_constant(s, rhs_reg, slot_flonum_constant(t, op->op2));
        } else if (rhs_reg == dst_reg) {
          // Preserve the divisor across the quotient calculation when the
          // allocator reuses the RHS register for the result.
          rhs_reg = FRTMP;
          emit_fmov(s, rhs_reg, arg1_reg);
        }
        emit_fdiv(s, dst_reg, arg0_reg, rhs_reg);
        emit_ftruncate(s, dst_reg, dst_reg);
        emit_fmul(s, dst_reg, dst_reg, rhs_reg);
        emit_fsub(s, dst_reg, arg0_reg, dst_reg);
      } else {
        emit_fixnum_binop_const(s, t, op, dst_reg, arg0_reg, arg1_reg, cur_snap,
                                emit_mod, emit_mod_constant);
      }
      break;
    }
      EMIT_GUARDED_ARITH_CASE(IR_ADD, emit_fadd,
                              asm_emit_fixnum_add_guard_overflow,
                              asm_emit_fixnum_add_constant_guard_overflow)
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
    case IR_INTEGER_CHAR: {
      assert(op->type == CHAR_TAG);
      assert(!is_fpr_reg(dst_reg));
      emit_shl_constant(s, dst_reg, arg0_reg, 8 - FIXNUM_SHIFT);
      emit_add_constant(s, dst_reg, dst_reg, CHAR_TAG);
      break;
    }
    case IR_CHAR_INTEGER: {
      assert(op->type == FIXNUM_TAG);
      assert(!is_fpr_reg(dst_reg));
      emit_sar_constant(s, dst_reg, arg0_reg, 8 - FIXNUM_SHIFT);
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
      // Note emit_typecheck uses RTMP
      uint8_t load_reg = op->type == FLONUM_TAG ? RTMP2 : dst_reg;
      emit_mem_load(s, (int32_t)op->data * 8, RSTACK, load_reg);
      emit_typecheck(s, t, op, cur_snap, load_reg);
      if (op->type == FLONUM_TAG) {
        emit_fmem_load(s, 8 - FLONUM_TAG, load_reg, dst_reg);
      }
      break;
    }
    case IR_GGET: {
      emit_heap_constant(s, t, RTMP, slot_gc_obj(t, op->op1));
      emit_mem_load(s, 16 - SYMBOL_TAG, RTMP, dst_reg);
      emit_typecheck(s, t, op, cur_snap, dst_reg);
      break;
    }
    case IR_GSET: {
      emit_heap_constant(s, t, RTMP, slot_gc_obj(t, op->op1));
      uint8_t val_reg = emit_arg_reg(args, arg_regs, arg_count, op->op2);
      if (op->op2.constant) {
        val_reg = RTMP2;
        emit_heap_constant(s, t, val_reg, slot_gc_obj(t, op->op2));
      } else {
        assert(val_reg != REG_NONE);
      }
      emit_store(s, 16 - SYMBOL_TAG, RTMP, val_reg);
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
    case IR_STACK_STORE: {
      assert(op->op2.constant);
      uint8_t val_reg = arg0_reg;
      if (op->op1.constant) {
        val_reg = RTMP;
        emit_heap_constant(s, t, val_reg, slot_gc_obj(t, op->op1));
      } else {
        assert(val_reg != REG_NONE);
      }
      if (is_fpr_reg(val_reg)) {
        bool live_regs[MAX_REG];
        uint64_t live_gpr_mask;
        collect_live_roots(t, ra_state, op_cnt_idx, -1, live_regs,
                           &live_gpr_mask);
        emit_box_flonum(s, 0, val_reg, false, live_regs, live_gpr_mask);
        val_reg = RTMP;
      }
      int64_t stack_off = slot_const(t, op->op2);
      assert((int32_t)stack_off == stack_off);
      emit_store(s, (int32_t)stack_off, RSTACK, val_reg);
      break;
    }
    case IR_ALLOC: {
      assert(op->op2.constant);
      uint64_t type_val = (uint64_t)(slot_const(t, op->op2) >> FIXNUM_SHIFT);
      uint8_t tag_bits = (uint8_t)(type_val & TAG_MASK);
      bool live_regs[MAX_REG];
      uint64_t live_gpr_mask;
      collect_live_roots(t, ra_state, op_cnt_idx, -1, live_regs,
                         &live_gpr_mask);

      int64_t tagged_size = 0;
      uint8_t size_reg = REG_NONE;
      if (op->op1.constant) {
        tagged_size = slot_const(t, op->op1);
      } else {
        assert(arg0_reg != REG_NONE);
        size_reg = arg0_reg;
      }

      emit_rooted_alloc(s, live_gpr_mask, tagged_size, size_reg);
      emit_store_constant(s, 0, RTMP, (int64_t)type_val);
      if (type_val == VECTOR_TAG || type_val == RECORD_TAG ||
          type_val == CLOSURE_TAG) {
        asm_zero_alloc_payload(s, tagged_size, size_reg);
      }
      if (type_val == SYMBOL_TAG) {
        emit_store_constant(s, symbol_val_offset, RTMP, DEAD.value);
      }
      emit_add_constant(s, dst_reg, RTMP, tag_bits);
      break;
    }
    case IR_BOX_FLONUM: {
      assert(arg0_reg != REG_NONE);
      assert(is_fpr_reg(arg0_reg));
      assert(dst_reg != REG_NONE);
      assert(!is_fpr_reg(dst_reg));
      bool live_regs[MAX_REG];
      uint64_t live_gpr_mask;
      collect_live_roots(t, ra_state, op_cnt_idx, -1, live_regs,
                         &live_gpr_mask);
      emit_box_flonum(s, 0, arg0_reg, false, live_regs, live_gpr_mask);
      if (dst_reg != RTMP) {
        emit_mov(s, dst_reg, RTMP);
      }
      break;
    }
    case IR_CCALL: {
      emit_ccall(s, t, ra_state, op_cnt_idx, op, args, arg_regs, arg_count,
                 dst_reg);
      break;
    }
    case IR_FLUSH: {
      assert(cur_snap >= 0);
      emit_snap(s, t, (uint16_t)cur_snap, false);
      if (dst_reg != RSTACK) {
        emit_mov(s, dst_reg, RSTACK);
      }
      break;
    }
    case IR_CALLCC: {
      emit_callcc(s, t, ra_state, op_cnt_idx, op, args, arg_regs, arg_count,
                  dst_reg);
      break;
    }
    case IR_CALLCC_RESUME: {
      emit_callcc_resume(s, t, ra_state, op_cnt_idx, op, args, arg_regs,
                         arg_count);
      break;
    }
    case IR_VMADD:
    case IR_VMSUB:
    case IR_VMMUL:
    case IR_VMDIV:
    case IR_VMQUOTIENT:
    case IR_VMMOD:
    case IR_VMLT:
    case IR_VMGT:
    case IR_VMLTE:
    case IR_VMGTE:
    case IR_VMJEQV:
    case IR_VMJNEQV:
    case IR_VMINEXACT:
    case IR_VMEXACT:
    case IR_VMTRUNCATE: {
      emit_vmcall(s, t, ra_state, op_cnt_idx, op, args, arg_regs, arg_count,
                  dst_reg, cur_snap);
      break;
    }
    case IR_REF:
    case IR_CARG:
    case IR_ARG:
    case IR_NOP:
    case IR_PMOV:
      break;
    case IR_TYPECHECK: {
      emit_typecheck(s, t, op, cur_snap, arg0_reg);
      if (is_fpr_reg(out_reg)) {
        emit_unbox_flonum(s, arg0_reg, out_reg);
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
      emit_mov64(s, RTMP, spill_base(op->type));
      if (op->type == FLONUM_TAG) {
        emit_fstore(s, spill_offset(op->spill), RTMP, out_reg);
      } else {
        emit_store(s, spill_offset(op->spill), RTMP, out_reg);
      }
    }
    // TODO: maybe move emit_typecheck here, instead of each individual one.
  }

  // Some traces place entry/exit snapshots immediately after the final IR.
  // Those still need labels and snapshot lifetime updates for linked entry.
  while (snap_idx < arrlen(t->snaps) && t->snaps[snap_idx].ir == op_cnt_idx) {
    if (snap_idx == 1) {
      emit_label(s, &t->snap_entry_label);
    }
    if (snap_idx > 0) {
      regalloc_maybe_free_snapshot(ra_state, op_cnt_idx,
                                   &t->snaps[snap_idx - 1]);
    }
    cur_snap = (int32_t)snap_idx;
    snap_idx++;
  }
}

// Emit *two* entry points:
// One that loops back from the current trace
// One from c.
static void emit_root_trace_entry(emit_state *s, trace *t,
                                  regalloc_state *ra_state) {
  regalloc_state arg_state;
  regalloc_state_init(&arg_state, t);
  // Emit an entry point from C.
  COMMENT("CENTRY");
  save_callee_regs(s);
  emit_load_ralloc(s);
  emit_mov(s, RSTATE, RARG0);
  emit_mov(s, RSTACK, RARG1);

  ir_ins *arg_ins = nullptr;
  for_each_leading_op(t, IR_ARG, arg_ins) {
    uint16_t ir_idx = (uint16_t)(arg_ins - t->ins);
    regalloc_assign_output(&arg_state, ir_idx, arg_ins);
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
  regalloc_state_free(&arg_state);
  (void)ra_state;
}

static void emit_side_trace_entry(emit_state *s, trace *t,
                                  regalloc_state *ra_state) {
  (void)ra_state;
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
  regalloc_state reg_state;
  regalloc_state_init(&reg_state, t);

  // Remember, we're emitting backwards? This makes the register
  // allocator much simpler to write, no state needs to be preserved.
  emit_writable_begin(s);

  // Emit a return-to-c stub.
  // TODO: could be shared by ALL traces
  auto start = emit_offset(s);
  t->code_start = (uint8_t *)start;

  if (!t->parent_snap) {
    emit_root_trace_entry(s, t, &reg_state);
  } else {
    emit_side_trace_entry(s, t, &reg_state);
  }

  // This is where the trace will start when other traces are linked to it.
  // (without typechecking).
  emit_label(s, &t->trace_start);

  emit_ir(s, t, &reg_state);

  // Link to the next trace: Which is either ourselves (if a looping parent
  // trace), or another trace (if a side trace).
  link_to_next_trace(s, t, link_entry_snap);

  label exit_label = {};
  // Exist stubs for all but the loopback (last). These restore the scheme
  // stack state, putting any in-register values back on the stack, and boxing
  // flonums.
  auto end_no_snapshots = emit_offset(s);
  emit_snapshot_exits(s, t, t->snaps, &exit_label);

  emit_label(s, &exit_label);
  emit_exit_to_c(s);
  auto end = emit_offset(s);
  t->code_end = (uint8_t *)end;

  emit_constant_pool(s);
  emit_writable_end(s);

  auto sz = end - start;
  if (verbose) {
    printf("Disassembly: %" PRId64 "\n", sz);
    disassemble((uint8_t *)start, end_no_snapshots - start, s->comments);
  }

  if (verbose) {
    print_ir(t);
  }

  // Cleanup
  arr_for_each(s->comments, entry) { free((void *)entry.text); }
  arrfree(s->comments);
  regalloc_state_free(&reg_state);

  // Install debuginfo for gdb & linux perf tool.
  char funcname[256];
  char *dumpname = t->parent_snap ? "SIDE" : "TRACE";
  snprintf(funcname, sizeof(funcname), "%s_%i", dumpname, t->num);
  register_jit_symbol((uint8_t *)start, (uint8_t *)start, (uint8_t *)end,
                      funcname);
  // Call the built-in function to flush the cache for the specific range
  __builtin___clear_cache((char *)start, (char *)emit_offset(s));
  return (trace_fn)start;
}
