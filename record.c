#include <assert.h>
#include <stdlib.h>

#include "array.h"
#include "bc.h"
#include "emit.h"
#include "hawk.h"
#include "ir.h"
#include "record.h"
#include "string.h"
#include "types.h"
#include "vm.h"

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

static void vm_add_snap(vm_state *state, bc *pc) {
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  snap snap = {
      .pc = pc,
      .offset = ts->stack_off,
      .ir = arrlen(cur_trace->ins),
      .depth = ts->depth,
      .exits = 0,
      .trace = cur_trace,
  };
  snapshot_live_slots(ts, &snap);
  arrput(nullptr, cur_trace->snaps, snap);
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

static void set_stack(vm_state *state, uint8_t reg, slot val) {
  auto entry = get_sentry(state, reg);
  *entry = (sentry){
      .live = true,
      .changed = true,
      .loc = val,
  };
}

static slot stack_load(vm_state *state, gc_obj *stack, uint8_t pos) {
  auto entry = get_sentry(state, pos);
  if (entry->live) {
    return entry->loc;
  }
  // emit stack load
  ir_ins ins = (ir_ins){
      .op = IR_SLOAD, .data = pos, .reg = REG_NONE, .spill = SPILL_NONE};

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
static slot emit_ov_math_add(vm_state *state, slot v1, slot v2) {
  // TODO fold for consts.
  ir_ins ins = (ir_ins){
      .op = IR_ADD, .op1 = v1, .op2 = v2, .reg = REG_NONE, .spill = SPILL_NONE};
  return add_inst(state, ins);
}
static slot emit_ov_math_sub(vm_state *state, slot v1, slot v2) {
  // TODO fold for consts.
  ir_ins ins = (ir_ins){
      .op = IR_SUB, .op1 = v1, .op2 = v2, .reg = REG_NONE, .spill = SPILL_NONE};
  return add_inst(state, ins);
}
static slot emit_math_cmp_lt(vm_state *state, slot v1, slot v2) {
  // TODO fold for consts.
  ir_ins ins = (ir_ins){
      .op = IR_LT, .op1 = v1, .op2 = v2, .reg = REG_NONE, .spill = SPILL_NONE};
  return add_inst(state, ins);
}
static void ensure_symbol(slot val) {}
static slot constify_data(vm_state *state, uint16_t data) {
  gc_obj c = (gc_obj){.value = data};
  return add_const(state, c);
}
static void record_abort(vm_state *state) {
  // TODO this needs to return correct impl, and clear current trace.
  abort();
}
static frame_state return_frame(vm_state *state, bc *pc, gc_obj *stack) {
  if (record_trace_state(state)->depth == 0) {
    // Root traces cannot return
    if (!record_current_trace(state)->parent) {
      printf("Record abort: return\n");
      record_abort(state);
    }
    // Side traces *may* go down the stack.
    // 1) record load for result
    auto res = stack_load(state, stack, pc->op);
    // 2) get the frame offset
    auto ra = to_return_address(stack[-1]);
    auto old_pc = ra - 1;
    auto offset = old_pc->reg + 1;
    // 3) Clear regs / set result in new regs
    assert(record_trace_state(state)->stack_off == 0);
    arrlen_set(record_trace_state(state)->stack, 0);
    // 4) Const-ify the current return address
    // TODO(davejwatson) this const_ra needs to be updated by the GC.
    auto const_ra = add_const(state, stack[-1]);
    auto const_offset = add_const(state, tag_fixnum(offset));
    // 5) add a new IR: IR_RET that checks ret and does a ret.
    ir_ins ins = {.op = IR_RET,
                  .op1 = const_offset,
                  .op2 = const_ra,
                  .reg = REG_NONE,
                  .spill = SPILL_NONE,
                  .type = UNDEFINED_TAG};
    add_inst(state, ins);
    // 6) set new stack top.
    set_stack(state, old_pc->reg, res);
    // 7) Add a snap, since we changed the stack / RA, we can't go back.
    vm_add_snap(state, ra);
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
  return (frame_state){pc, stack};
}
static bc *next_op(bc *pc) { return pc; }
static gc_obj halt(vm_state *state, gc_obj *stack) {
  (void)state;
  printf("DONE\n");
  return stack[0];
}

static slot sym_load(vm_state *state, slot sym) {
  ir_ins ins =
      (ir_ins){.op = IR_GGET, .op1 = sym, .reg = REG_NONE, .spill = SPILL_NONE};
  return add_inst(state, ins);
}
static void prepare_call(gc_obj fun) { printf("prepare call\n"); }
static void check_arity(gc_obj fun, gc_obj args) {}
static bc *branch_if_false(vm_state *state, bc *pc, gc_obj *stack, slot b) {
  // TODO: move AFTER branch
  vm_add_snap(state, pc);
  // We're going to directly peek at the stack here.
  auto res = stack[pc->reg];
  // TODO:snapshot
  slot must_be = add_const(state, res);

  ir_ins ins = (ir_ins){.op = IR_GUARD_EQ,
                        .op1 = b,
                        .op2 = must_be,
                        .reg = REG_NONE,
                        .spill = SPILL_NONE};
  add_inst(state, ins);

  return pc;
}
static slot closure_get(vm_state *state, slot clo, uint8_t pos) {
  slot c_pos = (slot){.constant = true, .loc = pos + 8 - CLOSURE_TAG};

  ir_ins ins = (ir_ins){.op = IR_LOAD,
                        .op1 = clo,
                        .op2 = c_pos,
                        .reg = REG_NONE,
                        .spill = SPILL_NONE};
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
static bc *set_new_pc(vm_state *state, bc *pc, gc_obj *stack, slot func) {
  if (!func.constant) {
    // Func isn't a constant, we need a runtime check.
    // Peek at destination
    slot must_be = add_const(state, stack[pc->reg]);

    ir_ins ins = (ir_ins){.op = IR_GUARD_EQ,
                          .op1 = func,
                          .op2 = must_be,
                          .reg = REG_NONE,
                          .spill = SPILL_NONE};
    add_inst(state, ins);
  }

  return pc;
}
static void record_finish(bc *pc, vm_state *state) {
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  vm_add_snap(state, pc);
  print_ir(cur_trace);
  cur_trace->num = arrlen(state->record.traces);
  cur_trace->fn = emit(cur_trace, &state->emit, &state->record);
  print_ir(cur_trace);
  state->max_trace--;
  if (!cur_trace->parent) {
    *ts->start_ins = (bc){
        .op = OP_JFUNC,
        .data = record_trace_count(state),
    };
  }
  record_append_trace(state, cur_trace);
}
static void *jit_func(bc **pc, gc_obj **stack, vm_state *state,
                      void *op_table) {
  // LINK IT!
  auto cur_trace = record_current_trace(state);
  if (cur_trace->parent) {
    cur_trace->link = (*pc)->data;
    record_finish(*pc, state);
    return state->impls;
  } else {
    // TODO
    abort();
  }
}
static void *check_record_start(bc *pc, gc_obj *stack, vm_state *state,
                                void *op_table) {
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  if (pc == ts->start_ins) {
    cur_trace->link = arrlen(state->record.traces);
    record_finish(pc, state);
    return state->impls;
  }
  return op_table;
}

// Tailcall to the non-recording version, which will then tailcall the
// next *recording* opcode
#define dispatch_next(pc, stack)                                               \
  op_func impl = state->impls[(pc)->op];                                       \
  MUSTTAIL return impl(pc, stack, state, op_table, 0);

#define VMGEN_TRACE_OP(code)                                                   \
  do {                                                                         \
    printf("record op: %s\n", #code);                                          \
  } while (0)
#include "vmgen.c"

void record_start(vm_state *state, bc *pc, gc_obj *stack) {
  printf("Record start\n");
  record_set_current_trace(state, calloc(1, sizeof(trace)));
  trace_state *ts = record_trace_state(state);
  memset(ts, 0, sizeof(trace_state));
  ts->start_ins = pc;
  vm_add_snap(state, pc);
}

void record_start_side(vm_state *state, bc *pc, gc_obj *stack, snap *snap) {
  printf("Record start side\n");
  record_set_current_trace(state, calloc(1, sizeof(trace)));
  trace_state *ts = record_trace_state(state);
  record_current_trace(state)->parent = snap->trace;
  record_current_trace(state)->parent_snap = snap;
  memset(ts, 0, sizeof(trace_state));
  ts->start_ins = pc;
  ts->depth = snap->depth;
  vm_add_snap(state, pc);
}
