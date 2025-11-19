#include <assert.h>
#include <stdlib.h>

#include "array.h"
#include "bc.h"
#include "emit.h"
#include "hawk.h"
#include "ir.h"
#include "opt_dce.h"
#include "record.h"
#include "string.h"
#include "types.h"
#include "vm.h"

// TODO: record abort if depth > ~20
// TODO: record abort if len > ~4000

#define VMGEN_TRACE_OP(pc, code)                                               \
  do {                                                                         \
    if (verbose) {                                                             \
      printf("record op: %p %s\n", pc, #code);                                 \
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
  PRESERVE_NONE gc_obj record_##code(bc *pc, gc_obj *stack, vm_state *state,   \
                                     void *op_table, uint8_t argcnt)

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
  if (arrlen(cur_trace->snaps) && arrlast(cur_trace->snaps)->ir == sn.ir) {
    // TODO arrpop
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
      assert(ins->type == get_type_tag(stack[pos]));
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
static void add_typecheck(ir_ins *ins, gc_obj *stack, uint8_t loc) {
  ins->type = get_type_tag(stack[loc]);
  ins->guard = true;
}
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
static slot emit_ov_math_sub(vm_state *state, slot v1, slot v2) {
  // TODO fold for consts.
  auto t = record_current_trace(state);
  if (get_slot_type(t, v1) != get_slot_type(t, v2)) {
    abort();
  }
  ir_ins ins =
      IR(.op = IR_SUB, .op1 = v1, .op2 = v2, .type = get_slot_type(t, v1));
  return add_inst(state, ins);
}
static slot emit_math_cmp_lt(vm_state *state, slot v1, slot v2) {
  (void)state;
  (void)v2;
  return v1;
}
static slot emit_math_cmp_eq(vm_state *state, slot v1, slot v2) {
  (void)state;
  (void)v2;
  return v1;
}
static void ensure_symbol(slot val) {}
static slot constify_data(vm_state *state, uint16_t data) {
  gc_obj c = (gc_obj){.value = data};
  return add_const(state, c);
}
static void record_abort(vm_state *state) {
  free_trace(record_current_trace(state));
  clear_trace_state(record_trace_state(state));
}
static void record_finish(bc *pc, vm_state *state) {
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  vm_add_snap(state, pc);
  cur_trace->num = arrlen(state->record.traces);
  dce(cur_trace);
  if (verbose) {
    print_ir(cur_trace);
  }
  cur_trace->fn = emit(cur_trace, &state->emit, &state->record);
  if (verbose) {
    print_ir(cur_trace);
  }
  state->max_trace--;
  if (!cur_trace->parent) {
    *ts->start_ins = (bc){
        .op = OP_JFUNC,
        .data = record_trace_count(state),
    };
  }
  record_append_trace(state, cur_trace);
  clear_trace_state(ts);
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
  if (record_trace_state(state)->depth == 0) {
    // Root traces cannot return
    if (!record_current_trace(state)->parent &&
        !is_downrec_trace(record_trace_state(state))) {
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
    int cnt = 0;
    arr_for_each(record_trace_state(state)->downrec, downrec_ra) {
      if (downrec_ra == pc) {
        cnt++;
      }
    }

    // If this is a side trace, we've detected potential downrecursion.
    // Abort and start a downrec trace.
    if (record_current_trace(state)->parent && cnt) {
      if (verbose) {
        printf("Record abort: potential downrec detected\n");
      }
      clear_trace_state(record_trace_state(state));
      free_trace(record_current_trace(state));
      record_start(state, pc, stack);
      // UGH there must be a better way?
      VMGEN_TRACE_OP(pc, RET);
      return return_frame(state, pc, stack, op_table);
    }
    if (is_downrec_trace(record_trace_state(state)) && cnt) {
      record_current_trace(state)->link = record_current_trace(state);
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
    assert(record_trace_state(state)->stack_off == 0);
    arrlen_set(record_trace_state(state)->stack, 0);
    // 4) Const-ify the current return address

    auto const_ra = add_const(state, stack[-1]);
    auto const_offset = add_const(state, tag_fixnum(offset));
    // 5) add a new IR: IR_RET that checks ret and does a ret.
    ir_ins ins = IR(.op = IR_RET, .op1 = const_offset, .op2 = const_ra,
                    .type = get_type_tag(stack[pc->reg]));
    add_inst(state, ins);
    // 6) set new stack top.
    set_stack(state, old_pc->reg, res);
    // 7) Add a snap, since we changed the stack / RA, we can't go back.
    vm_add_snap(state, ra);
    arrput(nullptr, record_trace_state(state)->downrec, pc);
  } else {
    record_trace_state(state)->depth--;
    abort();
    /* auto ret = state->stack[state->stack_offset + func->reg]; */
    /* auto pc = to_return_address(stack[-1]); */
    /* auto old_pc = pc - 1; */
    /* state->stack_offset -= old_pc->reg + 1; */
    /* state->stack[state->stack_offset + old_pc->reg] = ret; */
    /* arrlen_set(state->stack, state->stack_offset + old_pc->reg + 1); */
  }
  return (frame_state){pc, stack, op_table};
}
static bc *next_op(bc *pc) { return pc; }
static gc_obj halt(vm_state *state, gc_obj *stack) {
  (void)state;
  return stack[0];
}

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
static void obj_write(vm_state *state, slot val) { abort(); }
static void prepare_call(gc_obj fun) { printf("prepare call\n"); }
// Nothing necessary for record - we will check in emit_snapshot - checks will
// be elided if we never hit a snapshot!
static inline void check_expand_stack(vm_state *state, gc_obj **stack) {}
static inline void fail_if_not_closure(slot sym) {
  // TODO?
}
static void check_arity(int fun, uint8_t args) {
  // TODO
}
static bc *branch_if_op(vm_state *state, bc *pc, gc_obj *stack, slot b) {
  trace_state *ts = record_trace_state(state);
  auto t = record_current_trace(state);
  bool res;
  ir_ins ins;
  switch (pc->op) {
  case OP_IF: {
    auto val = stack[pc->data];
    res = val.value != FALSE_REP.value;
    slot must_be = add_const(state, res ? TRUE_REP : FALSE_REP);
    ins = IR(.op = IR_GUARD_EQ, .op1 = b, .op2 = must_be);
    break;
  }
  case OP_JLT: {
    auto lhs = stack[pc->v1];
    auto rhs = stack[pc->v2];
    res = to_fixnum(lhs) < to_fixnum(rhs);
    slot lhs_slot = stack_load(state, stack, pc->v1, false);
    slot rhs_slot = stack_load(state, stack, pc->v2, false);
    ins = IR(.op = res ? IR_LT : IR_GTE, .op1 = lhs_slot, .op2 = rhs_slot,
             .type = UNDEFINED_TAG);
    break;
  }
  case OP_JEQV: {
    auto lhs = stack[pc->v1];
    auto rhs = stack[pc->v2];
    res = to_fixnum(lhs) == to_fixnum(rhs);
    slot lhs_slot = stack_load(state, stack, pc->v1, false);
    slot rhs_slot = stack_load(state, stack, pc->v2, false);
    ins = IR(.op = res ? IR_EQ : IR_NE, .op1 = lhs_slot, .op2 = rhs_slot,
             .type = get_slot_type(t, lhs_slot));
    break;
  }
  default:
    abort();
  }

  // pc->reg is the new top of stack.  Clear out anything above before
  // snapshotting.
  arrlen_set(ts->stack, pc->reg);

  auto jmp_pc = pc + 1;
  bc *next_pc;
  if (!res) {
    next_pc = jmp_pc + jmp_pc->data;
    vm_add_snap(state, jmp_pc + 1);
  } else {
    next_pc = jmp_pc + 1;
    vm_add_snap(state, jmp_pc + jmp_pc->data);
  }

  add_inst(state, ins);
  vm_add_snap(state, next_pc);
  return pc;
}
static slot closure_get(vm_state *state, slot clo, uint8_t pos) {
  // Store byte offset to the captured variable (header is 16 bytes).
  slot c_pos =
      (slot){.constant = true, .loc = (uint16_t)((pos * 8) + 8 - CLOSURE_TAG)};

  if (clo.constant) {
    auto trace = record_current_trace(state);
    auto c = to_closure(trace->consts[clo.loc]);
    auto res = c->v[pos];
    return add_const(state, res);
  }
  ir_ins ins = IR(.op = IR_LOAD, .op1 = clo, .op2 = c_pos);
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
  arrlen_set(ts->stack, to + ts->stack_off);
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
static void *jit_func(bc **pc, gc_obj **stack, vm_state *state,
                      void *op_table) {
  // LINK IT!
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
  if (cur_trace->parent) {
    cur_trace->link = state->record.traces[(*pc)->data];
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
  if (pc == ts->start_ins) {
    if (ts->skip_start_check) {
      ts->skip_start_check = false;
      return op_table;
    }
    cur_trace->link = cur_trace;
    record_finish(pc, state);
    return state->impls;
  }
  return op_table;
}

// Tailcall to the non-recording version, which will then tailcall the
// next *recording* opcode
#define dispatch_next(pc, stack)                                               \
  op_func impl = state->impls[(pc)->op];                                       \
  MUSTTAIL return impl(pc, stack, state, op_table, argcnt);

#include "vmgen.c"

void record_start(vm_state *state, bc *pc, gc_obj *stack) {
  if (verbose) {
    printf("Record start %li\n", arrlen(state->record.traces));
  }
  record_set_current_trace(state, calloc(1, sizeof(trace)));
  record_current_trace(state)->start_pc = *pc;
  trace_state *ts = record_trace_state(state);
  memset(ts, 0, sizeof(trace_state));
  ts->start_ins = pc;
  ts->skip_start_check = (pc->op == OP_RET);

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
  record_current_trace(state)->parent = snap->trace;
  record_current_trace(state)->parent_snap = snap;
  record_current_trace(state)->start_pc = *pc;
  memset(ts, 0, sizeof(trace_state));
  ts->start_ins = pc;
  ts->skip_start_check = (pc->op == OP_RET);
  ts->depth = snap->depth;

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
        set_stack(state, entry->slot,
                  add_inst(state, IR(.op = IR_PMOV, .data = old_ins->reg,
                                     .type = old_ins->type)));
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
}
