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
#include "hawk.h"
#include "ir.h"
#include "vm.h"
#ifdef HAVE_ELF_H
#include "jitdump.h"
#endif
#include "parallel_copy.h"
#include "record.h"
#include "zone_alloc.h"

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
    bool done = false;
    for (int j = 0; j < MAX_REG; j++) {
      if (!s->reg_to_slot[j].used) {
        op->reg = j;
        s->reg_to_slot[op->reg].s = sl->val.loc;
        s->reg_to_slot[op->reg].used = true;
        done = true;
        // lru_poke(&reg_lru, op->reg);
        /* printf("Assigning snap register %s to op %i\n",
         * reg_names[op->reg], sl->val); */
        break;
      }
    }
    if (!done) {
      // Couldn't find a free reg, assign a slot.
      op->spill = (s->next_spill)++;
      /* printf("Assigning snap slot %i to op %i\n", op->slot, sl->val); */
      assert(s->next_spill < 255);
      // check_spill_cnt(s->next_spill);
    }
  }
}
// Get a specific reg, spilling if necessary.
static void get_reg(emit_state *s, uint8_t reg, trace *trace) {
  if (s->reg_to_slot[reg].used) {
    /* // printf("Spilling reg %s\n", reg_names[reg]); */
    /* auto op = s->reg_to_slot[reg]; */
    /* assert(trace->ops[op].reg != REG_NONE); */

    /* auto spill = trace->ops[op].slot; */
    /* if (trace->ops[op].slot == SLOT_NONE) { */
    /*   spill = (s->next_spill)++; */
    /*   check_spill_cnt(s->next_spill); */
    /* } */

    /* trace->ops[op].slot = spill; */
    /* emit_mem_reg(OP_MOV_MR, 0, RTMP, trace->ops[op].reg); */
    /* emit_mov64(RTMP, (int64_t)&spill_slot[trace->ops[op].slot]); */
    /* trace->ops[op].reg = REG_NONE; */
    /* s->reg_to_slot[reg] = -1; */
    /* lru_poke(&reg_lru, reg); */
    abort();
  }
  s->reg_to_slot[reg].used = true;
}
static int get_free_reg(emit_state *s, trace *trace, bool callee) {
  for (int i = 0; i < MAX_REG; i++) {
    if (!s->reg_to_slot[i].used) {
      return i;
    }
  }

  abort();
  // Spill.

  // get_reg(oldest, trace, s->next_spill, slot);
  // return oldest;
}
static void maybe_assign_register(emit_state *s, slot v, trace *trace) {
  if (!v.constant) {
    auto op = &trace->ins[v.loc];
    if (op->reg == REG_NONE) {
      op->reg = get_free_reg(s, trace, false);
      s->reg_to_slot[op->reg].s = v.loc;
      s->reg_to_slot[op->reg].used = true;
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
} ignoremap;

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
    if (reg >= MAX_REG) {
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
  if ((count & 1) && count > 0) {
    regs[count] = regs[count - 1];
    count++;
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

  // TODO: move all this to another stub, so we're not exploding code size with
  // all these push/pops.  We can just CALL stub directly.
  for (size_t i = regs_cnt; i > 0; i--) {
    emit_pop(s, regs_to_save[i - 1]);
  }
  emit_mov(s, RSTACK, RET_REG);
  emit_call_reg(s, RTMP);

  emit_mov64(s, RTMP, (intptr_t)&jit_expand_stack_slowpath);
  emit_mov(s, RARG0, RSTATE);
  emit_mov(s, RARG1, RSTACK);
  for (size_t i = 0; i < regs_cnt; i++) {
    emit_push(s, regs_to_save[i]);
  }

  emit_jcc32(s, JL, done);
  emit_cmp(s, RSTACK, RTMP);
  emit_mem_load(s, (int32_t)offsetof(vm_state, stack_limit), RSTATE, RTMP);
  COMMENT("Emit stack guard check");
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
    abort();
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
      }
      break;
    }
    if (!found) {
      abort();
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
    emit_mov64(s, map->target_reg, map->constant_value);
  }
}

static void emit_parallel_moves(emit_state *s, par_copy *cpy,
                                ignoremap *loopback_regs) {
  emit_loopback_constants(s, loopback_regs);
  par_copy *moves = serialize_parallel_copy(cpy, RTMP);
  arr_reverse(moves);
  arr_for_each_idx(moves, i) {
    auto mov = moves[i];
    emit_mov(s, mov.to, mov.from);
  }
  arrfree(cpy);
  arrfree(moves);
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
    if (reg_map->reg == REG_NONE) {
      abort();
    }
    arrput(nullptr, cpy,
           ((par_copy){.from = reg_map->reg, .to = arg_ins->reg}));
  }
  emit_parallel_moves(s, cpy, loopback_regs);
}

static void emit_snap(emit_state *s, trace *t, snap *snap, bool exit,
                      ignoremap *ignore) {
  // If this is an exiting snapshot (vs. a loop back)
  // then record exit PC & snapshot.
  if (exit) {
    emit_mov64(s, RET_REG2, (intptr_t)snap);
    emit_mov(s, RET_REG, RSTACK);
  }

  // TODO ignoremap .reg may still be live.

  emit_stack_offset_and_check(s, snap, ignore);

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
    if (op->reg != REG_NONE && op->reg != RSTACK && op->op != IR_ARG) {
      assert(s->reg_to_slot[op->reg].s == op_cnt);
      s->reg_to_slot[op->reg].used = false;
    }

    emit_check(s);
    switch (op->op) {
    case IR_GUARD_EQ: {
      emit_jcc32(s, JNE, t->snaps[cur_snap].patch_point);
      emit_cmp_slots(s, t, op->op1, op->op2);
      break;
    }
    case IR_EQ: {
      emit_jcc32(s, JNE, t->snaps[cur_snap].patch_point);
      emit_cmp_slots(s, t, op->op1, op->op2);
      break;
    }
    case IR_NE: {
      emit_jcc32(s, JE, t->snaps[cur_snap].patch_point);
      emit_cmp_slots(s, t, op->op1, op->op2);
      break;
    }
    case IR_LOAD: {
      maybe_assign_register(s, op->op1, t);
      assert(!op->op1.constant);
      emit_mem_load(s, (uint16_t)op->op2.loc + 8, slot_reg(t, op->op1),
                    op->reg);
      break;
    }
    case IR_LT: {
      emit_jcc32(s, JGE, t->snaps[cur_snap].patch_point);
      emit_cmp_slots(s, t, op->op1, op->op2);
      break;
    }
    case IR_GT: {
      emit_jcc32(s, JLE, t->snaps[cur_snap].patch_point);
      emit_cmp_slots(s, t, op->op1, op->op2);
      break;
    }
    case IR_GTE: {
      emit_jcc32(s, JL, t->snaps[cur_snap].patch_point);
      emit_cmp_slots(s, t, op->op1, op->op2);
      break;
    }
    case IR_SUB: {
      emit_arith_slots(s, t, op->reg, op->op1, op->op2, true);
      break;
    }
    case IR_ADD: {
      emit_arith_slots(s, t, op->reg, op->op1, op->op2, false);
      break;
    }
    case IR_SLOAD: {
      emit_mem_load(s, (int32_t)op->data * 8, RSTACK, op->reg);
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
      emit_jcc32(s, JNE, t->snaps[cur_snap].patch_point);
      emit_cmp_constant(s, op->reg, slot_const(t, op->op2));
      // cmp stack[-1], jmp to snap if not equal
      emit_mem_load(s, -8, RSTACK, op->reg);
      /* if (t->num == 1 && op_cnt == 6) { */
      /*   emit_jmp32(s, snap_labels[cur_snap]); */
      /*   COMMENT("ABORT"); */
      /* } */

      break;
    }
    case IR_ARG:
    case IR_NOP:
    case IR_PMOV:
      // Done at end.
      break;
    default: {
      printf("Can't jit op: %s\n", ir_names[op->op]);
      abort();
      // exit(-1);
    }
    }
    COMMENT("%i %s", op_cnt, ir_names[op->op]);
  }
}

// Emit *two* entry points:
// One that loops back from the current trace
// One from c.
static void emit_root_trace_entry(emit_state *s, trace *t,
                                  ignoremap *loopback_regs) {
  size_t snap_cnt = arrlen(t->snaps);
  if (!snap_cnt) {
    return;
  }
  // Emit a loopbackentry point
  // emit parcopy from loop end
  collect_loopback_parallel_moves(s, t, loopback_regs);

  if (t->link == t) { // self link
    emit_jmp32_patch_here(s, t->snaps[arrlen(t->snaps) - 1].patch_point);
  }
  COMMENT("LOOPBACK ENTRY");

  // Emit an entry point from C.
  emit_jmp32(s, t->trace_start);
  ir_ins *arg_ins = nullptr;
  for_each_leading_op(t, IR_ARG, arg_ins) {
    if (arg_ins->spill != SPILL_NONE) {
      abort();
    }
    if (arg_ins->reg != REG_NONE) {
      emit_mem_load(s, (int32_t)arg_ins->data * 8, RSTACK, arg_ins->reg);
    }
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
             ((par_copy){.from = pmov_ins->data, .to = pmov_ins->reg}));
    }
  }
  auto res = serialize_parallel_copy(cpy, RTMP);
  arr_reverse(res);
  arr_for_each(res, mov) { emit_mov(s, mov.to, mov.from); }
  arrfree(cpy);
  arrfree(res);
  COMMENT("PARALLEL COPY FROM PARENT:");

  // Install the side trace.
  emit_jmp32_patch_here(s, (int64_t)t->parent_snap->patch_point);
  __builtin___clear_cache((char *)t->parent_snap->patch_point,
                          (char *)t->parent_snap->patch_point + 16);
}

static void emit_finish_snap_exits(emit_state *s, trace *t,
                                   int64_t exit_label) {
  // Emit even MORE snap exits.  We didn't have register allocation
  // previously, but now we do. Since these are slowpath exists, the extra
  // branches probably don't matter much.
  for (uint64_t i = arrlen(t->snaps) - 1; i > 0; i--) {
    snap *snap = &t->snaps[i - 1];
    emit_jmp32(s, exit_label);
    emit_snap(s, t, snap, true, nullptr);
    emit_jmp32_patch_here(s, t->snaps[i - 1].patch_point);
    COMMENT("Snap exit #%i", i - 1);
  }
}

trace_fn emit(trace *t, emit_state *s, record_state *record) {
  // Initialize asm emitter memory if not already done (once per process)
  emit_init(s);

  // Remember, we're emitting backwards! This makes the register
  // allocator much simpler to write, no state needs to be preserved.

  emit_writable_begin(s);
  memset(s->reg_to_slot, 0, sizeof(s->reg_to_slot));

  // Set up register allocator.
  bool reserved[MAX_REG] = {0};
  asm_mark_unallocatable(reserved);
  for (int i = 0; i < MAX_REG; i++) {
    s->reg_to_slot[i].used = reserved[i];
  }
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
    emit_root_trace_entry(s, t, loopback_regs);
  } else {
    emit_side_trace_entry(s, t);
  }
  auto entry = emit_offset(s);

  emit_finish_snap_exits(s, t, exit_label);

  emit_writable_end(s);
  auto sz = end - emit_offset(s);
  if (verbose) {
    printf("Disassembly: %" PRId64 "\n", sz);
    arr_reverse(s->comments);
    disassemble((uint8_t *)emit_offset(s), sz, s->comments);
  }

  // Cleanup
  zone_free(&s->z);
  s->comments = nullptr;
  arrfree(loopback_regs);

  // Install debuginfo for gdb & linux perf tool.
#ifdef HAVE_ELF_H
  if (jit_dump_flag) {
    jit_reader_add((int)(end - entry), entry);
    char *dumpname = t->parent ? "Side Trace" : "Trace";
    jit_dump((int)sz, emit_offset(s), dumpname);
    perf_map(emit_offset(s), sz, dumpname);
  }
#endif
  // Call the built-in function to flush the cache for the specific range
  __builtin___clear_cache((char *)emit_offset(s), (char *)emit_offset(s) + sz);
  return (trace_fn)entry;
}
