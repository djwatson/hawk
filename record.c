#include <stdlib.h>

#include "bc.h"
#include "hawk.h"
#include "ir.h"
#include "string.h"
#include "types.h"
#include "vec.h"
#include "emit.h"

typedef struct {
  bool changed;
  bool live;
  slot loc;
} sentry;

VEC_TYPE_IMPL(ins, ir_ins);
VEC_TYPE_IMPL(consts, gc_obj);
VEC_TYPE_IMPL(sentry, sentry);
VEC_TYPE_IMPL(snap, snap);
VEC_TYPE_IMPL(snap_entry, snap_entry);

typedef struct {
  sentry *stack;
  uint16_t stack_off;
  bc *start_ins;
  uint8_t depth;
} trace_state;

// TODO merge type shit
typedef struct {
  bc *pc;
  gc_obj *stack;
} frame_state;

// TODO not global
static trace *cur_trace;
static trace_state ts;

#define OP(code)                                                               \
  PRESERVE_NONE gc_obj record_##code(bc *pc, gc_obj *stack, void *op_table,    \
                                     uint8_t argcnt)
typedef gc_obj PRESERVE_NONE (*op_func)(bc *pc, gc_obj *stack, void *op_table,
                                        uint8_t argcnt);
extern op_func impls[OP_INS_MAX];
extern op_func record_impls[OP_INS_MAX];
// end TODO

static void vm_add_snap(bc *pc) {
  snap snap = {.pc = pc,
                 .offset = ts.stack_off,
                 .ir = arrlen_ins(cur_trace->ins),
                 .exits = 0};
  for (size_t i = 0; i < arrlen_sentry(ts.stack); i++) {
    if (ts.stack[i].changed && ts.stack[i].live) {
      snap_entry entry = {.slot = (uint16_t)i, .val = ts.stack[i].loc};
      arrpush_snap_entry(&snap.slots, entry);
    }
  }
  arrpush_snap(&cur_trace->snaps, snap);
}

static sentry *get_sentry(uint64_t idx) {
  auto len = arrlen_sentry(ts.stack);
  while (len++ <= (idx + ts.stack_off)) {
    sentry entry = {.live = false, .changed = false};
    arrpush_sentry(&ts.stack, entry);
  }
  return &ts.stack[idx + ts.stack_off];
}

static  slot stack_load(gc_obj *stack, uint8_t pos) {
  auto entry = get_sentry(pos);
  if (entry->live) {
    return entry->loc;
  }
  // emit stack load
  ir_ins ins = (ir_ins){
      .op = IR_SLOAD, .data = pos, .reg = REG_NONE, .spill = SPILL_NONE};

  // Save in instructions array
  auto idx = arrlen_ins(cur_trace->ins);
  arrpush_ins(&cur_trace->ins, ins);

  // Save instr slot in our shadow regs, and return!.
  slot n = (slot){.constant = false, .loc = idx};
  entry->live = true;
  entry->changed = false;
  entry->loc = n;
  return n;
}
static  void stack_save(gc_obj *stack, uint8_t pos, slot res) {
  auto entry = get_sentry(pos);
  entry->live = true;
  entry->changed = true;
  entry->loc = res;
}
static  slot const_load(bc *pc, uint16_t offset) {
  // We use a non-moving gc, so this is just a runtime constant, always.
  auto c = *(gc_obj *)(pc - pc->data);
  // Save it to consts array
  auto idx = arrlen_consts(cur_trace->consts);
  arrpush_consts(&cur_trace->consts, c);
  return (slot){.constant = true, .loc = idx};
}
static  slot emit_ov_math_add(slot v1, slot v2) {
  // TODO fold for consts.
  ir_ins ins = (ir_ins){
      .op = IR_ADD, .op1 = v1, .op2 = v2, .reg = REG_NONE, .spill = SPILL_NONE};
  auto idx = arrlen_ins(cur_trace->ins);
  arrpush_ins(&cur_trace->ins, ins);
  return (slot){.constant = false, .loc = idx};
}
static  slot emit_ov_math_sub(slot v1, slot v2) {
  // TODO fold for consts.
  ir_ins ins = (ir_ins){
      .op = IR_SUB, .op1 = v1, .op2 = v2, .reg = REG_NONE, .spill = SPILL_NONE};
  auto idx = arrlen_ins(cur_trace->ins);
  arrpush_ins(&cur_trace->ins, ins);
  return (slot){.constant = false, .loc = idx};
}
static  slot emit_math_cmp_lt(slot v1, slot v2) {
  // TODO fold for consts.
  ir_ins ins = (ir_ins){
      .op = IR_LT, .op1 = v1, .op2 = v2, .reg = REG_NONE, .spill = SPILL_NONE};
  auto idx = arrlen_ins(cur_trace->ins);
  arrpush_ins(&cur_trace->ins, ins);
  return (slot){.constant = false, .loc = idx};
}
static  void ensure_symbol(slot val) {}
static  slot constify_data(uint16_t data) {
  // Save in constants array
  auto idx = arrlen_consts(cur_trace->consts);
  gc_obj c = (gc_obj){.value = data};
  arrpush_consts(&cur_trace->consts, c);

  // return as a slot.
  slot n = (slot){.constant = true, .loc = idx};
  return n;
}
static  frame_state return_frame(bc *pc, gc_obj *stack) {
  // TODO
  vm_add_snap(pc);
  printf("return_frame\n");
  abort();
  return (frame_state){pc, stack};
}
static  bc *next_op(bc *pc) { return pc; }
static  gc_obj halt(gc_obj *stack) {
  printf("DONE\n");
  return stack[0];
}

static  slot sym_load(slot sym) {
  ir_ins ins =
      (ir_ins){.op = IR_GGET, .op1 = sym, .reg = REG_NONE, .spill = SPILL_NONE};
  auto idx = arrlen_ins(cur_trace->ins);
  arrpush_ins(&cur_trace->ins, ins);

  return (slot){.constant = false, .loc = idx};
}
static  void prepare_call(gc_obj fun) { printf("prepare call\n"); }
static  void check_arity(gc_obj fun, gc_obj args) {}
static  bc *branch_if_false(bc *pc, gc_obj *stack, slot b) {
  // TODO: move AFTER branch
  vm_add_snap(pc);
  // We're going to directly peek at the stack here.
  auto res = stack[pc->reg];
  // TODO:snapshot
  auto c_idx = arrlen_consts(cur_trace->consts);
  arrpush_consts(&cur_trace->consts, res);
  slot must_be = (slot){.constant = true, .loc = c_idx};

  ir_ins ins = (ir_ins){.op = IR_GUARD_EQ,
                        .op1 = must_be,
                        .op2 = b,
                        .reg = REG_NONE,
                        .spill = SPILL_NONE};
  arrpush_ins(&cur_trace->ins, ins);

  return pc;
}
static  slot closure_get(slot clo, uint8_t pos) {
  slot c_pos = (slot){.constant = true, .loc = pos};

  ir_ins ins = (ir_ins){.op = IR_LOAD,
                        .op1 = clo,
                        .op2 = c_pos,
                        .reg = REG_NONE,
                        .spill = SPILL_NONE};
  auto idx = arrlen_ins(cur_trace->ins);
  arrpush_ins(&cur_trace->ins, ins);
  return (slot){.constant = false, .loc = idx};
}
static  slot return_address(bc *ra) {
  auto c_idx = arrlen_consts(cur_trace->consts);
  arrpush_consts(&cur_trace->consts, tag_return_address(ra));
  return (slot){.constant = true, .loc = c_idx};
}
static  gc_obj *adjust_stack_depth(gc_obj *stack, int depth) {
  ts.stack_off += depth;
  ts.depth++;
  return stack;
}
static  bc *set_new_pc(bc *pc, gc_obj *stack, slot func) {
  if (!func.constant) {
    // Func isn't a constant, we need a runtime check.
    // Peek at destination
    auto c_idx = arrlen_consts(cur_trace->consts);
    arrpush_consts(&cur_trace->consts, stack[pc->reg]);
    slot must_be = (slot){.constant = true, .loc = c_idx};

    ir_ins ins = (ir_ins){.op = IR_GUARD_EQ,
                          .op1 = must_be,
                          .op2 = func,
                          .reg = REG_NONE,
                          .spill = SPILL_NONE};
    arrpush_ins(&cur_trace->ins, ins);
  }

  return pc;
}
static  void *check_record_start(bc *pc, gc_obj *stack, void *op_table) {
  if (pc == ts.start_ins) {
    vm_add_snap(pc);
    printf("Record done\n");
    print_ir(cur_trace);
    emit(cur_trace);
    exit(0);
    return impls;
  }
  return op_table;
}

// Tailcall to the non-recording version, which will then tailcall the
// next *recording* opcode
#define dispatch_next(pc, stack)                                               \
  op_func impl = ((op_func *)impls)[(pc)->op];                                 \
  MUSTTAIL return impl(pc, stack, op_table, 0);

#include "vmgen.c"

void record_start(bc *pc, gc_obj *stack) {
  printf("Record start\n");
  cur_trace = calloc(1, sizeof(trace));
  memset(&ts, 0, sizeof(ts));
  ts.start_ins = pc;
  vm_add_snap(pc);
}
