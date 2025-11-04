#include <stdlib.h>

#include "bc.h"
#include "hawk.h"
#include "ir.h"
#include "string.h"
#include "types.h"
#include "vec.h"

VEC_TYPE_IMPL(ins, ir_ins);
VEC_TYPE_IMPL(consts, gc_obj);

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

static inline slot stack_load(gc_obj *stack, uint8_t pos) {
  if (ts.live[pos]) {
    return ts.regs[pos];
  }
  // emit stack load
  ir_ins ins = (ir_ins){
      .op = IR_SLOAD, .data = pos, .reg = REG_NONE, .spill = SPILL_NONE};

  // Save in instructions array
  auto idx = arrlen_ins(cur_trace->ins);
  arrpush_ins(&cur_trace->ins, ins);

  // Save instr slot in our shadow regs, and return!.
  slot n = (slot){.constant = false, .loc = idx};
  ts.regs[pos] = n;
  ts.live[pos] = true;
  return n;
}
static inline void stack_save(gc_obj *stack, uint8_t pos, slot res) {
  ts.regs[pos] = res;
  ts.live[pos] = true;
}
static inline slot const_load(bc *pc, uint16_t offset) {
  // We use a non-moving gc, so this is just a runtime constant, always.
  auto c = *(gc_obj *)(pc - pc->data);
  // Save it to consts array
  auto idx = arrlen_consts(cur_trace->consts);
  arrpush_consts(&cur_trace->consts, c);
  return (slot){.constant = true, .loc = idx};
}
static inline slot emit_ov_math_add(slot v1, slot v2) {
  // TODO fold for consts.
  ir_ins ins = (ir_ins){
      .op = IR_ADD, .op1 = v1, .op2 = v2, .reg = REG_NONE, .spill = SPILL_NONE};
  auto idx = arrlen_ins(cur_trace->ins);
  arrpush_ins(&cur_trace->ins, ins);
  return (slot){.constant = false, .loc = idx};
}
static inline slot emit_ov_math_sub(slot v1, slot v2) {
  // TODO fold for consts.
  ir_ins ins = (ir_ins){
      .op = IR_SUB, .op1 = v1, .op2 = v2, .reg = REG_NONE, .spill = SPILL_NONE};
  auto idx = arrlen_ins(cur_trace->ins);
  arrpush_ins(&cur_trace->ins, ins);
  return (slot){.constant = false, .loc = idx};
}
static inline slot emit_math_cmp_lt(slot v1, slot v2) {
  // TODO fold for consts.
  ir_ins ins = (ir_ins){
      .op = IR_LT, .op1 = v1, .op2 = v2, .reg = REG_NONE, .spill = SPILL_NONE};
  auto idx = arrlen_ins(cur_trace->ins);
  arrpush_ins(&cur_trace->ins, ins);
  return (slot){.constant = false, .loc = idx};
}
static inline void ensure_symbol(slot val) {}
static inline slot constify_data(uint16_t data) {
  // Save in constants array
  auto idx = arrlen_consts(cur_trace->consts);
  gc_obj c = (gc_obj){.value = data};
  arrpush_consts(&cur_trace->consts, c);

  // return as a slot.
  slot n = (slot){.constant = true, .loc = idx};
  return n;
}
static inline frame_state return_frame(bc *pc, gc_obj *stack) {
  printf("return_frame\n");
  return (frame_state){pc, stack};
}
static inline bc *next_op(bc *pc) { return pc; }
static inline gc_obj halt(gc_obj *stack) {
  printf("DONE\n");
  return stack[0];
}

static inline slot sym_load(slot sym) {
  ir_ins ins =
      (ir_ins){.op = IR_GGET, .op1 = sym, .reg = REG_NONE, .spill = SPILL_NONE};
  auto idx = arrlen_ins(cur_trace->ins);
  arrpush_ins(&cur_trace->ins, ins);

  return (slot){.constant = false, .loc = idx};
}
static inline void prepare_call(gc_obj fun) { printf("prepare call\n"); }
static inline void check_arity(gc_obj fun, gc_obj args) {}
static inline bc *branch_if_false(bc *pc, gc_obj *stack, slot b) {
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
  auto idx = arrlen_ins(cur_trace->ins);
  arrpush_ins(&cur_trace->ins, ins);

  return pc;
}
static inline slot closure_get(slot clo, uint8_t pos) {
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
static inline slot return_address(bc *ra) {
  auto c_idx = arrlen_consts(cur_trace->consts);
  arrpush_consts(&cur_trace->consts, tag_return_address(ra));
  return (slot){.constant = true, .loc = c_idx};
}
static inline gc_obj *adjust_stack_depth(gc_obj *stack, int depth) {
  ts.regs_off += depth;
  ts.depth++;
  return stack;
}
static inline bc *set_new_pc(bc *pc, gc_obj *stack, slot func) {
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
    auto idx = arrlen_ins(cur_trace->ins);
    arrpush_ins(&cur_trace->ins, ins);
  }

  return pc;
}
static inline void *check_record_start(bc *pc, gc_obj *stack, void *op_table) {
  if (pc == ts.start_ins) {
    printf("Record done\n");
    print_ir(cur_trace);
    exit(0);
    return impls;
  }
  return op_table;
}

// Tailcall to the non-recording version, which will then tailcall the
// next *recording* opcode
#define dispatch_next(pc, stack)                                               \
  op_func impl = ((op_func *)impls)[pc->op];                                   \
  MUSTTAIL return impl(pc, stack, op_table, 0);

#include "vmgen.c"

void record_start(bc *pc, gc_obj *stack) {
  printf("Record start\n");
  cur_trace = malloc(sizeof(trace));
  cur_trace->ins = nullptr;
  cur_trace->consts = nullptr;
  cur_trace->stackpos = 0;
  ts.start_ins = pc;
  ts.regs_off = 0;
  ts.depth = 0;
  memset(ts.live, 0, sizeof(ts.live));
}
