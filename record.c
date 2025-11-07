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

// TODO merge type shit
typedef struct {
  bc *pc;
  gc_obj *stack;
} frame_state;

#define TRACE_STATE(state) (&(state)->record.trace_state)
#define CUR_TRACE(state) ((state)->record.cur_trace)
#define TRACES(state) ((state)->record.traces)

#define OP(code)                                                               \
  PRESERVE_NONE gc_obj record_##code(bc *pc, gc_obj *stack, vm_state *state,   \
                                     void *op_table, uint8_t argcnt)
// end TODO

static void vm_add_snap(vm_state *state, bc *pc) {
  auto *ts = TRACE_STATE(state);
  auto *cur_trace = CUR_TRACE(state);
  snap snap = {
      .pc = pc,
      .offset = ts->stack_off,
      .ir = arrlen(cur_trace->ins),
      .exits = 0,
      .trace = cur_trace,
  };
  arr_for_each_idx(ts->stack, i) {
    if (ts->stack[i].changed && ts->stack[i].live) {
      snap_entry entry = {.slot = (uint16_t)i, .val = ts->stack[i].loc};
      arrput(nullptr, snap.slots, entry);
    }
  }
  arrput(nullptr, cur_trace->snaps, snap);
}

static sentry *get_sentry(vm_state *state, uint64_t idx) {
  auto *ts = TRACE_STATE(state);
  auto len = arrlen(ts->stack);
  while (len++ <= (idx + ts->stack_off)) {
    sentry entry = {.live = false, .changed = false};
    arrput(nullptr, ts->stack, entry);
  }
  return &ts->stack[idx + ts->stack_off];
}

static slot stack_load(vm_state *state, gc_obj *stack, uint8_t pos) {
  auto entry = get_sentry(state, pos);
  if (entry->live) {
    return entry->loc;
  }
  // emit stack load
  ir_ins ins = (ir_ins){
      .op = IR_SLOAD, .data = pos, .reg = REG_NONE, .spill = SPILL_NONE};

  // Save in instructions array
  auto idx = arrlen(CUR_TRACE(state)->ins);
  arrput(nullptr, CUR_TRACE(state)->ins, ins);

  // Save instr slot in our shadow regs, and return!.
  slot n = (slot){.constant = false, .loc = idx};
  entry->live = true;
  entry->changed = false;
  entry->loc = n;
  return n;
}
static void stack_save(vm_state *state, gc_obj *stack, uint8_t pos, slot res) {
  auto entry = get_sentry(state, pos);
  entry->live = true;
  entry->changed = true;
  entry->loc = res;
}
static slot const_load(vm_state *state, bc *pc, uint16_t offset) {
  // We use a non-moving gc, so this is just a runtime constant, always.
  auto c = *(gc_obj *)(pc - pc->data);
  // Save it to consts array
  auto idx = arrlen(CUR_TRACE(state)->consts);
  arrput(nullptr, CUR_TRACE(state)->consts, c);
  return (slot){.constant = true, .loc = idx};
}
static slot emit_ov_math_add(vm_state *state, slot v1, slot v2) {
  // TODO fold for consts.
  ir_ins ins = (ir_ins){
      .op = IR_ADD, .op1 = v1, .op2 = v2, .reg = REG_NONE, .spill = SPILL_NONE};
  auto idx = arrlen(CUR_TRACE(state)->ins);
  arrput(nullptr, CUR_TRACE(state)->ins, ins);
  return (slot){.constant = false, .loc = idx};
}
static slot emit_ov_math_sub(vm_state *state, slot v1, slot v2) {
  // TODO fold for consts.
  ir_ins ins = (ir_ins){
      .op = IR_SUB, .op1 = v1, .op2 = v2, .reg = REG_NONE, .spill = SPILL_NONE};
  auto idx = arrlen(CUR_TRACE(state)->ins);
  arrput(nullptr, CUR_TRACE(state)->ins, ins);
  return (slot){.constant = false, .loc = idx};
}
static slot emit_math_cmp_lt(vm_state *state, slot v1, slot v2) {
  // TODO fold for consts.
  ir_ins ins = (ir_ins){
      .op = IR_LT, .op1 = v1, .op2 = v2, .reg = REG_NONE, .spill = SPILL_NONE};
  auto idx = arrlen(CUR_TRACE(state)->ins);
  arrput(nullptr, CUR_TRACE(state)->ins, ins);
  return (slot){.constant = false, .loc = idx};
}
static void ensure_symbol(slot val) {}
static slot constify_data(vm_state *state, uint16_t data) {
  // Save in constants array
  auto idx = arrlen(CUR_TRACE(state)->consts);
  gc_obj c = (gc_obj){.value = data};
  arrput(nullptr, CUR_TRACE(state)->consts, c);

  // return as a slot.
  slot n = (slot){.constant = true, .loc = idx};
  return n;
}
static frame_state return_frame(vm_state *state, bc *pc, gc_obj *stack) {
  // TODO
  vm_add_snap(state, pc);
  printf("return_frame\n");
  abort();
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
  auto idx = arrlen(CUR_TRACE(state)->ins);
  arrput(nullptr, CUR_TRACE(state)->ins, ins);

  return (slot){.constant = false, .loc = idx};
}
static void prepare_call(gc_obj fun) { printf("prepare call\n"); }
static void check_arity(gc_obj fun, gc_obj args) {}
static bc *branch_if_false(vm_state *state, bc *pc, gc_obj *stack, slot b) {
  // TODO: move AFTER branch
  vm_add_snap(state, pc);
  // We're going to directly peek at the stack here.
  auto res = stack[pc->reg];
  // TODO:snapshot
  auto c_idx = arrlen(CUR_TRACE(state)->consts);
  arrput(nullptr, CUR_TRACE(state)->consts, res);
  slot must_be = (slot){.constant = true, .loc = c_idx};

  ir_ins ins = (ir_ins){.op = IR_GUARD_EQ,
                        .op1 = must_be,
                        .op2 = b,
                        .reg = REG_NONE,
                        .spill = SPILL_NONE};
  arrput(nullptr, CUR_TRACE(state)->ins, ins);

  return pc;
}
static slot closure_get(vm_state *state, slot clo, uint8_t pos) {
  slot c_pos = (slot){.constant = true, .loc = pos + 8 - CLOSURE_TAG};

  ir_ins ins = (ir_ins){.op = IR_LOAD,
                        .op1 = clo,
                        .op2 = c_pos,
                        .reg = REG_NONE,
                        .spill = SPILL_NONE};
  auto idx = arrlen(CUR_TRACE(state)->ins);
  arrput(nullptr, CUR_TRACE(state)->ins, ins);
  return (slot){.constant = false, .loc = idx};
}
static slot return_address(vm_state *state, bc *ra) {
  auto c_idx = arrlen(CUR_TRACE(state)->consts);
  arrput(nullptr, CUR_TRACE(state)->consts, tag_return_address(ra));
  return (slot){.constant = true, .loc = c_idx};
}
static gc_obj *adjust_stack_depth(vm_state *state, gc_obj *stack, int depth) {
  auto *ts = TRACE_STATE(state);
  ts->stack_off += depth;
  ts->depth++;
  return stack;
}
static bc *set_new_pc(vm_state *state, bc *pc, gc_obj *stack, slot func) {
  if (!func.constant) {
    // Func isn't a constant, we need a runtime check.
    // Peek at destination
    auto c_idx = arrlen(CUR_TRACE(state)->consts);
    arrput(nullptr, CUR_TRACE(state)->consts, stack[pc->reg]);
    slot must_be = (slot){.constant = true, .loc = c_idx};

    ir_ins ins = (ir_ins){.op = IR_GUARD_EQ,
                          .op1 = must_be,
                          .op2 = func,
                          .reg = REG_NONE,
                          .spill = SPILL_NONE};
    arrput(nullptr, CUR_TRACE(state)->ins, ins);
  }

  return pc;
}
static void *jit_func(bc **pc, gc_obj **stack, vm_state *state,
                      void *op_table) {
  (void)state;
  abort();
}
static void *check_record_start(bc *pc, gc_obj *stack, vm_state *state,
                                void *op_table) {
  auto *ts = TRACE_STATE(state);
  auto *cur_trace = CUR_TRACE(state);
  if (pc == ts->start_ins) {
    vm_add_snap(state, pc);
    cur_trace->fn = emit(cur_trace);
    print_ir(cur_trace);
    // exit(0);
    state->max_trace--;
    *ts->start_ins = (bc){
        .op = OP_JFUNC,
        .data = arrlen(TRACES(state)),
    };
    arrput(nullptr, TRACES(state), cur_trace);
    return state->impls;
  }
  return op_table;
}

// Tailcall to the non-recording version, which will then tailcall the
// next *recording* opcode
#define dispatch_next(pc, stack)                                               \
  op_func impl = state->impls[(pc)->op];                                       \
  MUSTTAIL return impl(pc, stack, state, op_table, 0);

#include "vmgen.c"

void record_start(vm_state *state, bc *pc, gc_obj *stack) {
  printf("Record start\n");
  CUR_TRACE(state) = calloc(1, sizeof(trace));
  memset(TRACE_STATE(state), 0, sizeof(trace_state));
  TRACE_STATE(state)->start_ins = pc;
  vm_add_snap(state, pc);
}
