#include <assert.h>
#include <stdlib.h>

#include "array.h"
#include "bc.h"
#include "emit.h"
#include "gc.h"
#include "hawk.h"
#include "ir.h"
#include "opt_dce.h"
#include "record.h"
#include "string.h"
#include "types.h"
#include "vm.h"
#include "vm_guard.h"

// TODO: record abort if depth > ~20
// TODO: record abort if len > ~4000

#define VMGEN_TRACE_OP(pc, code, state)                                        \
  do {                                                                         \
    if (verbose) {                                                             \
      printf("record op: %p %s\n", pc, #code);                                 \
    }                                                                          \
    if ((state)->record.patchpc) {                                             \
      *(state)->record.patchpc = (state)->record.old_patch;                    \
      (state)->record.patchpc = nullptr;                                       \
    }                                                                          \
  } while (0)
static bool is_downrec_trace(trace_state *ts) {
  return ts->start_ins->op == OP_RET;
}

static void clear_trace_state(trace_state *ts) {
  arrfree(ts->stack);
  arrfree(ts->downrec);
}
static void free_snap(snap *snap) { arrfree(snap->slots); }
static void free_trace(trace *trace) {
  arr_for_each(trace->snaps, snap) { free_snap(&snap); }
  arrfree(trace->ins);
  arrfree(trace->consts);
  arrfree(trace->snaps);
  free(trace);
}
static inline trace_state *record_trace_state(vm_state *state) {
  return &state->record.trace_state;
}

static inline trace *record_current_trace(vm_state *state) {
  return state->record.cur_trace;
}

static inline void record_set_current_trace(vm_state *state, trace *trace) {
  state->record.cur_trace = trace;
}

static inline uint32_t record_trace_count(vm_state *state) {
  return arrlen(state->record.traces);
}

static inline void record_append_trace(vm_state *state, trace *trace) {
  arrput(nullptr, state->record.traces, trace);
}

static void snapshot_live_slots(trace_state *ts, snap *snap) {
  arr_for_each_idx(ts->stack, i) {
    sentry entry = ts->stack[i];
    if (entry.changed && entry.live) {
      snap_entry slot = {.slot = (uint16_t)i, .val = entry.loc};
      arrput(nullptr, snap->slots, slot);
    }
  }
}

#define OP(code)                                                               \
  PRESERVE_NONE gc_obj record_##code(bc instr, bc *pc, gc_obj *stack,          \
                                     vm_state *state, void *op_table,          \
                                     uint8_t argcnt)

typedef struct {
  bool taken;
  ir_ins guard;
} branch_result;

static void record_scan_roots(void *data, gc_scan_root_cb add_root) {
  record_state *record = data;
  trace *cur_trace = record->cur_trace;
  if (cur_trace && arrlen(cur_trace->consts) > 0) {
    add_root((uint64_t *)cur_trace->consts, arrlen(cur_trace->consts));
  }
  arr_for_each(record->traces, trace_obj) {
    if (trace_obj && arrlen(trace_obj->consts) > 0) {
      add_root((uint64_t *)trace_obj->consts, arrlen(trace_obj->consts));
    }
  }
}

void record_init(record_state *record) {
  gc_set_scan_callback(record_scan_roots, record);
}

static slot add_const(vm_state *state, gc_obj value) {
  trace *trace_obj = record_current_trace(state);
  auto idx = arrlen(trace_obj->consts);
  arrput(nullptr, trace_obj->consts, value);
  return (slot){.constant = true, .loc = idx};
}

#define IR(...)                                                                \
  IR_PRAGMA_DISABLE((ir_ins){.type = UNDEFINED_TAG,                            \
                             .guard = false,                                   \
                             .reg = REG_NONE,                                  \
                             .spill = SPILL_NONE,                              \
                             __VA_ARGS__})                                     \
  IR_PRAGMA_RESTORE

static void vm_add_snap(vm_state *state, bc *pc) {
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  snap sn = {
      .pc = pc,
      .offset = ts->stack_off,
      .ir = arrlen(cur_trace->ins),
      .depth = ts->depth,
      .exits = 0,
      .trace = cur_trace,
  };
  snapshot_live_slots(ts, &sn);
  // No need for duplicate snaps at the same IR.  use the newest.
  // TODO: watch out for removing first snap??? since that one is special and
  // means 'arg types don't match'.
  if (arrlen(cur_trace->snaps) && arrlast(cur_trace->snaps)->ir == sn.ir) {
    auto old = arrlast(cur_trace->snaps);
    arrpop(cur_trace->snaps);
    free_snap(old);
  }
  arrput(nullptr, cur_trace->snaps, sn);
}

static sentry *get_sentry(vm_state *state, uint64_t idx) {
  trace_state *ts = record_trace_state(state);
  auto len = arrlen(ts->stack);
  while (len++ <= (idx + ts->stack_off)) {
    sentry entry = {.live = false, .changed = false};
    arrput(nullptr, ts->stack, entry);
  }
  return &ts->stack[idx + ts->stack_off];
}

static inline void set_stack_len(trace_state *ts, uint32_t len) {
  arrlen_set(ts->stack, ts->stack_off + len);
}

static slot add_inst(vm_state *state, ir_ins ins) {
  trace *trace_obj = record_current_trace(state);
  auto idx = arrlen(trace_obj->ins);
  arrput(nullptr, trace_obj->ins, ins);
  return (slot){.constant = false, .loc = idx};
}

static uint8_t get_slot_type(trace *t, slot v) {
  if (v.constant) {
    return get_type_tag(t->consts[v.loc]);
  }
  return t->ins[v.loc].type;
}

static void set_stack(vm_state *state, uint8_t reg, slot val) {
  auto entry = get_sentry(state, reg);
  *entry = (sentry){
      .live = true,
      .changed = true,
      .loc = val,
  };
}

static slot stack_load(vm_state *state, gc_obj *stack, uint8_t pos,
                       bool typecheck) {
  auto entry = get_sentry(state, pos);
  if (entry->live) {
    auto res = entry->loc;
    if (typecheck & !res.constant) {
      auto ins = &record_current_trace(state)->ins[res.loc];
      // assert(ins->type == get_type_tag(stack[pos]));
      ins->guard = true;
    }
    return res;
  }
  // emit stack load
  ir_ins ins = IR(.op = IR_SLOAD, .data = pos, .type = get_type_tag(stack[pos]),
                  .guard = typecheck);

  set_stack(state, pos, add_inst(state, ins));
  entry->changed = false;
  return entry->loc;
}
static void stack_save(vm_state *state, gc_obj *stack, uint8_t pos, slot res) {
  set_stack(state, pos, res);
}
static slot const_load(vm_state *state, bc *pc, uint16_t offset) {
  // We use a non-moving gc, so this is just a runtime constant, always.
  auto c = *(gc_obj *)(pc - pc->data);
  return add_const(state, c);
}
static inline bc *vmgen_jmp_advance(bc *pc) { return pc; }
static slot emit_ov_math_add(vm_state *state, slot v1, slot v2) {
  // TODO fold for consts.
  auto t = record_current_trace(state);
  if (get_slot_type(t, v1) != get_slot_type(t, v2)) {
    abort();
  }
  ir_ins ins =
      IR(.op = IR_ADD, .op1 = v1, .op2 = v2, .type = get_slot_type(t, v1));
  return add_inst(state, ins);
}
static slot convert_to_flonum(vm_state *state, slot v1) {
  auto t = record_current_trace(state);
  auto t1 = get_slot_type(t, v1);
  if (t1 == FLONUM_TAG) {
    return v1;
  }
  if (t1 == FIXNUM_TAG) {
    if (v1.constant) {
      flonum_s *res = gc_alloc(sizeof(flonum_s));
      res->header.type = FLONUM_TAG;
      res->x = (double)to_fixnum(t->consts[v1.loc]);
      return add_const(state, tag_flonum(res));
    }
    ir_ins ins = IR(.op = IR_INEXACT, .op1 = v1, .type = FLONUM_TAG);
    return add_inst(state, ins);
  }
  abort();
}
static slot emit_ov_math_sub(vm_state *state, slot v1, slot v2) {
  // TODO fold for consts.
  auto t = record_current_trace(state);
  auto t1 = get_slot_type(t, v1);
  auto t2 = get_slot_type(t, v2);
  if (t1 == FLONUM_TAG || t2 == FLONUM_TAG) {
    v1 = convert_to_flonum(state, v1);
    v2 = convert_to_flonum(state, v2);
  } else if (t1 == FIXNUM_TAG && t2 == FIXNUM_TAG) {
    // OK.
  } else {
    abort();
  }
  ir_ins ins =
      IR(.op = IR_SUB, .op1 = v1, .op2 = v2, .type = get_slot_type(t, v1));
  return add_inst(state, ins);
}
static branch_result emit_math_cmp_lt(vm_state *state, bc *pc, gc_obj *stack,
                                      slot v1, slot v2) {
  auto lhs = stack[pc->v1];
  auto rhs = stack[pc->v2];
  bool res = to_fixnum(lhs) < to_fixnum(rhs);
  auto t = record_current_trace(state);
  auto t1 = get_slot_type(t, v1);
  auto t2 = get_slot_type(t, v2);
  if (t1 == FLONUM_TAG || t2 == FLONUM_TAG) {
    v1 = convert_to_flonum(state, v1);
    v2 = convert_to_flonum(state, v2);
  } else if (t1 == FIXNUM_TAG && t2 == FIXNUM_TAG) {
    // OK.
  } else {
    abort();
  }

  branch_result br = {
      .taken = res,
      .guard = IR(.op = res ? IR_LT : IR_GTE, .op1 = v1, .op2 = v2,
                  .type = get_slot_type(record_current_trace(state), v1)),
  };
  return br;
}
static branch_result emit_math_cmp_eq(vm_state *state, bc *pc, gc_obj *stack,
                                      slot v1, slot v2) {
  auto lhs = stack[pc->v1];
  auto rhs = stack[pc->v2];
  bool res = to_fixnum(lhs) == to_fixnum(rhs);

  auto t = record_current_trace(state);
  branch_result br = {
      .taken = res,
      .guard = IR(.op = res ? IR_EQ : IR_NE, .op1 = v1, .op2 = v2,
                  .type = get_slot_type(t, v1)),
  };
  return br;
}
static slot constify_data(vm_state *state, uint16_t data) {
  gc_obj c = (gc_obj){.value = data};
  return add_const(state, c);
}
// TODO remove, replace with instr vm usage
static void pend_patch(vm_state *state) {
  if ((state)->record.patchpc) {
    *(state)->record.patchpc = (state)->record.old_patch;
    (state)->record.patchpc = nullptr;
  }
}
static void record_abort(vm_state *state) {
  pend_patch(state);
  free_trace(record_current_trace(state));
  record_set_current_trace(state, nullptr);
  clear_trace_state(record_trace_state(state));
}
static void record_finish(bc *pc, vm_state *state) {
  pend_patch(state);
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  vm_add_snap(state, pc);
  cur_trace->num = arrlen(state->record.traces);
  dce(cur_trace);
  if (verbose) {
    print_ir(cur_trace);
  }
  cur_trace->fn = emit(cur_trace, &state->emit, &state->record, ts->poly_entry);
  if (verbose) {
    print_ir(cur_trace);
  }
  state->max_trace--;
  if (ts->type == TRACE_TYPE_ROOT) {
    *ts->start_ins = (bc){
        .op = OP_JFUNC,
        .data = record_trace_count(state),
    };
  }
  if (ts->type == TRACE_TYPE_POLY_ROOT) {
    assert(ts->poly_entry->trace->next == nullptr);
    ts->poly_entry->trace->next = cur_trace;
  }
  record_append_trace(state, cur_trace);
  clear_trace_state(ts);
}
static int downrec_hits(trace_state *ts, bc *pc) {
  int cnt = 0;
  arr_for_each(ts->downrec, downrec_ra) {
    if (downrec_ra == pc) {
      cnt++;
    }
  }
  return cnt;
}
static frame_state return_frame(vm_state *state, bc *pc, gc_obj *stack,
                                void *op_table) {
  // add downrec array
  // cases:
  // depth > 0:
  //   reduce depth and keep tracing.
  // depth == 0
  //   side/downrec trace:
  //     count downrec to this pc. If nonzero, abort and
  //     restart as downrec.
  //     downrec trace: capture!
  //   parent trace:
  //     if we're not yet at 'desperate' levels, abort and retry.
  //     if we're desperate, capture the trace, but mark as a 'desperate'
  //        future traces can trace through desperate instead of linking.
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  bool downrec_trace = is_downrec_trace(ts);
  bool at_trace_start = (pc == ts->start_ins);

  // for RET specifically: set stack top to pc->reg
  set_stack_len(ts, pc->reg + 1);

  if (ts->depth == 0) {
    // Root traces cannot return
    if (!cur_trace->parent && !downrec_trace) {
      if (verbose) {
        printf("Record abort: return\n");
      }
      record_abort(state);
      return (frame_state){pc, stack, state->impls};
    }

    // count returns NOTE that we're not checking against the
    // destination address, but the 'ret' address.  Otherwise we get
    // endless chains where there are two different return locations,
    // but the second one fails - and we don't save the downrec array
    // between traces, so the next side trace only also has two
    // downrec to two locations (although the first matches the first
    // in the parent trace).
    //
    // This may mean this ISN'T a downrecursive case, but if so, it
    // will eventually be blacklisted. Better to catch down-rec with
    // slight penalty for weird cases that look like downrec but aren't.
    int cnt = downrec_hits(ts, pc);
    bool seen_downrec = cnt > 0;

    // If this is a side trace, we've detected potential downrecursion.
    // Abort and start a downrec trace.
    if (cur_trace->parent && seen_downrec) {
      if (verbose) {
        printf("Record abort: potential downrec detected\n");
      }
      clear_trace_state(ts);
      free_trace(cur_trace);
      record_start(state, pc, stack, nullptr);
      // UGH there must be a better way?
      VMGEN_TRACE_OP(pc, RET, state);
      return return_frame(state, pc, stack, op_table);
    }
    if (downrec_trace && seen_downrec && at_trace_start) {
      cur_trace->link = cur_trace;
      if (verbose) {
        printf("Record stop: downrec\n");
      }
      record_finish(pc, state);
      return (frame_state){pc, stack, state->impls};
    }

    // Side traces *may* go down the stack.
    // 1) record load for result
    auto res = stack_load(state, stack, pc->reg, false);
    // 2) get the frame offset
    auto ra = to_return_address(stack[-1]);
    auto old_pc = ra - 1;
    auto offset = old_pc->reg + 1;

    // 3) Clear regs / set result in new regs
    // assert(ts->stack_off == 0);
    set_stack_len(ts, 0);
    // 4) Const-ify the current return address

    auto const_ra = add_const(state, stack[-1]);
    auto const_offset = add_const(state, tag_fixnum(offset));
    // 5) add a new IR: IR_RET that checks ret and does a ret.
    ir_ins ins = IR(.op = IR_RET, .op1 = const_offset, .op2 = const_ra,
                    // RET only manipulates the return address/stack pointer;
                    // keep it in a GPR regardless of value type.
                    .type = FIXNUM_TAG);
    add_inst(state, ins);
    // 6) set new stack top.
    set_stack(state, old_pc->reg, res);
    // 7) Add a snap, since we changed the stack / RA, we can't go back.
    vm_add_snap(state, ra);
    arrput(nullptr, ts->downrec, pc);
  } else {
    if (downrec_trace && at_trace_start && (arrlen(cur_trace->ins) > 1)) {
      // We've walked UP the stack to the same return statement somehow. Abort.
      if (verbose) {
        printf("Record abort: couldn't catch downrec, walked up.\n");
      }
      record_abort(state);
      return (frame_state){pc, stack, state->impls};
    }
    ts->depth--;
    assert(ts->depth >= 0);

    auto ret = stack_load(state, stack, pc->reg, false);
    auto new_pc = to_return_address(stack[-1]);
    auto old_pc = new_pc - 1;
    ts->stack_off -= (old_pc->reg + 1);
    // Trim traced stack to caller frame and store return value in caller slot.
    set_stack_len(ts, old_pc->reg + 1);
    stack_save(state, stack, old_pc->reg, ret);
  }
  return (frame_state){pc, stack, op_table};
}
static bc *next_op(bc *pc) { return pc; }
gc_obj halt(vm_state *state, gc_obj *stack);

static slot sym_load(vm_state *state, slot sym) {
  auto trace = record_current_trace(state);
  auto s = to_symbol(trace->consts[sym.loc]);
  if (s->opt >= 0) {
    s->opt = 1;
    return add_const(state, s->val);
  }
  ir_ins ins = IR(.op = IR_GGET, .op1 = sym);

  return add_inst(state, ins);
}
static void sym_store(vm_state *state, slot sym, slot val) {
  ir_ins ins = IR(.op = IR_GSET, .op1 = sym);
  add_inst(state, ins);
}
static void obj_write(vm_state *state, slot val, void **op_table) {
  if (verbose) {
    printf("Record abort: can't record WRITE\n");
  }
  record_abort(state);
  *op_table = state->impls;
}
static slot alloc_obj(vm_state *state, gc_obj *stack, bc *pc) {
  auto sz = stack_load(state, stack, pc->v1, true);
  auto type = stack_load(state, stack, pc->v2, true);
  assert(type.constant);
  if (!sz.constant) {
    if (verbose) {
      printf("Record abort: ALLOC size not constant\n");
    }
    record_abort(state);
    return (slot){0};
  }

  auto t = record_current_trace(state);
  auto type_const = t->consts[type.loc];
  ir_ins ins = IR(.op = IR_ALLOC, .op1 = sz, .op2 = type,
                  .type = (uint8_t)to_fixnum(type_const));
  return add_inst(state, ins);
}
static void store_obj(vm_state *state, gc_obj *stack, bc *pc) {
  auto obj = stack_load(state, stack, pc->reg, true);
  auto val = stack_load(state, stack, pc->v1, false);
  auto offset = stack_load(state, stack, pc->v2, true);

  auto ref = add_inst(state, IR(.op = IR_REF, .op1 = obj, .op2 = offset));
  add_inst(state, IR(.op = IR_STORE, .op1 = ref, .op2 = val,
                     .type = get_slot_type(record_current_trace(state), obj)));
}
static slot load_obj(vm_state *state, gc_obj *stack, bc *pc) {
  auto obj = stack_load(state, stack, pc->v1, true);
  auto offset = stack_load(state, stack, pc->v2, true);
  auto type = get_slot_type(record_current_trace(state), obj);

  ir_ins ins = IR(.op = IR_LOAD, .op1 = obj, .op2 = offset, .type = type);
  return add_inst(state, ins);
}
static slot guard_obj(vm_state *state, gc_obj *stack, bc *pc) {
  // Typecheck the object slot; SLOAD will emit the guard for us.
  stack_load(state, stack, pc->v1, true);
  auto want_tag = stack_load(state, stack, pc->v2, true);
  assert(want_tag.constant);
  bool matches = guard_obj_matches(stack[pc->v1], stack[pc->v2]);
  return add_const(state, matches ? TRUE_REP : FALSE_REP);
}
static void closure_set(vm_state *state, slot clo, uint8_t pos, slot val,
                        void **op_table) {
  if (verbose) {
    printf("Record abort: can't record CLOSURE_SET\n");
  }
  record_abort(state);
  *op_table = state->impls;
}
static slot closure_alloc(vm_state *state, gc_obj *stack, bc *pc) {
  (void)state;
  (void)stack;
  (void)pc;
  abort();
}
// Nothing necessary for record - we will check in emit_snapshot - checks will
// be elided if we never hit a snapshot!
static inline void check_expand_stack(vm_state *state, gc_obj **stack) {}
static inline void fail_if_not_closure(slot sym) {
  // TODO?
}
static void check_arity(int fun, uint8_t args) {
  // TODO
}
static branch_result emit_if_branch(vm_state *state, bc *pc, gc_obj *stack,
                                    slot cond) {
  auto val = stack[pc->data];
  bool taken = val.value != FALSE_REP.value;
  slot must_be = add_const(state, taken ? TRUE_REP : FALSE_REP);
  branch_result br = {
      .taken = taken,
      .guard = IR(.op = IR_GUARD_EQ, .op1 = cond, .op2 = must_be),
  };
  return br;
}
static bc *branch_if_op(vm_state *state, bc *pc, gc_obj *stack,
                        branch_result br) {
  trace_state *ts = record_trace_state(state);
  (void)stack;
  // pc->reg is the new top of stack.  Clear out anything above before
  // snapshotting.
  set_stack_len(ts, pc->reg);

  auto jmp_pc = pc + 1;
  bc *next_pc;
  if (!br.taken) {
    next_pc = jmp_pc + jmp_pc->data;
    vm_add_snap(state, jmp_pc + 1);
  } else {
    next_pc = jmp_pc + 1;
    vm_add_snap(state, jmp_pc + jmp_pc->data);
  }

  add_inst(state, br.guard);
  vm_add_snap(state, next_pc);
  return pc;
}
static slot closure_get(vm_state *state, gc_obj *stack, slot clo, uint8_t pos,
                        uint8_t clo_idx) {
  // Store byte offset to the captured variable (header is 16 bytes).
  slot c_pos =
      (slot){.constant = true, .loc = (uint16_t)((pos * 8) + 8 - CLOSURE_TAG)};

  if (clo.constant) {
    auto trace = record_current_trace(state);
    auto c = to_closure(trace->consts[clo.loc]);
    auto res = c->v[pos];
    return add_const(state, res);
  }
  gc_obj clo_obj = stack[clo_idx];
  gc_obj loaded = to_closure(clo_obj)->v[pos];

  ir_ins ins = IR(.op = IR_LOAD, .op1 = clo, .op2 = c_pos,
                  .type = (uint8_t)get_type_tag(loaded));
  return add_inst(state, ins);
}
static slot return_address(vm_state *state, bc *ra) {
  return add_const(state, tag_return_address(ra));
}
static gc_obj *adjust_stack_depth(vm_state *state, gc_obj *stack, int depth) {
  trace_state *ts = record_trace_state(state);
  ts->stack_off += depth;
  ts->depth++;
  return stack;
}
static void stack_memmov(vm_state *state, gc_obj *stack, uint16_t from,
                         uint16_t cnt) {
  trace_state *ts = record_trace_state(state);
  // The same as the VM:
  // memmove(&stack[0], &stack[from], cnt * sizeof(gc_obj));
  uint16_t to = 0;
  while (cnt-- > 0) {
    auto entry = stack_load(state, stack, from++, false);
    set_stack(state, to++, entry);
  }

  // Shrink stack to current stack top.
  set_stack_len(ts, to);
}
static bc *set_new_pc(vm_state *state, bc *pc, gc_obj *stack, slot func) {
  if (!func.constant) {
    // Func isn't a constant, we need a runtime check.
    // Peek at destination
    slot must_be = add_const(state, stack[pc->reg]);

    ir_ins ins = IR(.op = IR_GUARD_EQ, .op1 = func, .op2 = must_be);
    add_inst(state, ins);
  }

  return pc;
}

static trace *ensure_args_match_trace(gc_obj *stack, trace *head) {
  assert(head);
  for (trace *candidate = head; candidate; candidate = candidate->next) {
    bc *pc = &candidate->start_pc;
    auto argcnt = MIN(pc->reg, REG_ARG_CNT);
    bool match = true;
    for (int i = 0; i < argcnt; i++) {
      if ((size_t)i >= arrlen(candidate->ins)) {
        break;
      }
      ir_ins *ins = &candidate->ins[i];
      if (ins->op != IR_ARG || ins->data != (uint32_t)i) {
        continue;
      }
      if (ins->type != get_type_tag(stack[i])) {
        match = false;
        break;
      }
    }
    if (match) {
      return candidate;
    }
  }
  return nullptr;
}
static void *check_record_start(bc *pc, gc_obj *stack, vm_state *state,
                                void *op_table);
static void *jit_func(bc *instr, bc **pc, gc_obj **stack, vm_state *state,
                      void *op_table, uint8_t *argcnt) {
  // LINK IT!
  *instr = **pc;
  auto cur_trace = record_current_trace(state);
  // TODO can we clean this up?  side traces spawned from downrec traces aren't
  // downrec traces!
  if (is_downrec_trace(record_trace_state(state)) && !cur_trace->parent) {
    if (verbose) {
      printf("Record abort: can't downrec to JFUNC\n");
    }
    record_abort(state);
    return state->impls;
  }

  trace *target = state->record.traces[(*pc)->data];
  trace *matched = ensure_args_match_trace(*stack, target);
  if (!matched) {
    // Patchpc, record and run FUNC instead. Patch back after record & runing.
    state->record.old_patch = **pc;
    state->record.patchpc = *pc;
    **pc = target->start_pc;
    *instr = **pc;
    return check_record_start(*pc, *stack, state, op_table);
  }

  if (cur_trace->parent) {
    cur_trace->link = matched;
    if (verbose) {
      printf("Record stop: side trace linked to root trace\n");
    }
    record_finish(*pc, state);
    return state->impls;
  }
  // TODO
  abort();
}
static void *check_record_start(bc *pc, gc_obj *stack, vm_state *state,
                                void *op_table) {
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  // Several cases.
  // parent trace:
  //  depth == 0: tailcalled loop.
  //  depth != 0: up-recursion.
  // side trace:
  //  check for up-recursion and abort, restart trying to capture an
  //  up-recursive trace.
  if (pc == ts->start_ins && !is_downrec_trace(ts)) {
    if (ts->skip_start_check) {
      ts->skip_start_check = false;
      return op_table;
    }
    cur_trace->link = cur_trace;
    if (verbose) {
      printf("Record stop: root loop trace\n");
    }
    record_finish(pc, state);
    return state->impls;
  }
  return op_table;
}

// Tailcall to the non-recording version, which will then tailcall the
// next *recording* opcode
#define dispatch_next(pc, stack)                                               \
  op_func impl = state->impls[(pc)->op];                                       \
  MUSTTAIL return impl(*(pc), (pc), (stack), state, op_table, argcnt);

// NOLINTNEXTLINE(bugprone-suspicious-include)
#include "vmgen.c" // NOLINT(build/include)

void record_start(vm_state *state, bc *pc, gc_obj *stack,
                  const snap *poly_entry) {
  if (verbose) {
    printf("Record start %li\n", arrlen(state->record.traces));
  }
  record_set_current_trace(state, calloc(1, sizeof(trace)));
  if (pc->op == OP_JFUNC) {
    state->record.patchpc = pc;
    state->record.old_patch = *pc;
    *pc = state->record.traces[pc->data]->start_pc;
  }
  record_current_trace(state)->start_pc = *pc;
  trace_state *ts = record_trace_state(state);
  memset(ts, 0, sizeof(trace_state));
  ts->start_ins = pc;
  ts->skip_start_check = (pc->op == OP_RET);
  ts->type = poly_entry ? TRACE_TYPE_POLY_ROOT : TRACE_TYPE_ROOT;
  ts->poly_entry = poly_entry;

  vm_add_snap(state, pc);
  // OK! Let's put function arguments in registers.
  // Note these *must* be marked as 'changed', since ARGS aren't saved between
  // trace loops at all.
  assert(pc->op == OP_FUNC || pc->op == OP_RET);
  switch (pc->op) {
  case OP_FUNC:
    for (int i = 0; i < MIN(pc->reg, REG_ARG_CNT); i++) {
      set_stack(state, i,
                add_inst(state, IR(.op = IR_ARG, .data = i,
                                   .type = get_type_tag(stack[i]))));
    }
    break;
  case OP_RET:
    set_stack(state, pc->reg,
              add_inst(state, IR(.op = IR_ARG, .data = pc->reg,
                                 .type = get_type_tag(stack[pc->reg]))));
    break;
  default:
    abort();
  }
  vm_add_snap(state, pc);
}

void record_start_side(vm_state *state, bc *pc, gc_obj *stack, snap *snap) {
  if (verbose) {
    printf("Record start side %li\n", arrlen(state->record.traces));
  }
  record_set_current_trace(state, calloc(1, sizeof(trace)));
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  cur_trace->parent = snap->trace;
  cur_trace->parent_snap = snap;
  cur_trace->start_pc = *pc;
  memset(ts, 0, sizeof(trace_state));
  ts->start_ins = pc;
  ts->skip_start_check = (pc->op == OP_RET);
  ts->depth = snap->depth;
  ts->stack_off = snap->offset;
  ts->type = TRACE_TYPE_SIDE;

  vm_add_snap(state, pc);
  // Replay snapshot loads, so we keep things in register.
  arr_for_each_idx(snap->slots, j) {
    auto entry = &snap->slots[j];
    if (entry->val.constant) {
      set_stack(state, entry->slot,
                add_const(state, snap->trace->consts[entry->val.loc]));
    } else {
      auto old_ins = &snap->trace->ins[entry->val.loc];
      if (old_ins->spill != SPILL_NONE) {
        abort();
      } else {
        // We may have aborted because of a guard on PMOV, so we need to check
        // again.
        set_stack(
            state, entry->slot,
            add_inst(state, IR(.op = IR_PMOV, .prev_reg = old_ins->reg,
                               .prev_guard = old_ins->guard,
                               .type = get_type_tag(stack[entry->slot]))));
      }
    }
  }
  vm_add_snap(state, pc);
}

void free_traces(struct vm_state *state) {
  auto rs = &state->record;
  arr_for_each(rs->traces, trace) { free_trace(trace); }
  arrfree(rs->trace_state.stack);
  arrfree(rs->traces);
  rs->cur_trace = nullptr;
}
