// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ir.h"
#include "record.h"

enum : uint8_t {
  hotmap_sz = VM_HOTMAP_SZ,
  hotmap_loop = 3,
  hotmap_mask = (hotmap_sz - 1),
  hotmap_rec = 1,
  hotmap_cnt = 200,
};

static inline uint32_t hotmap_hash(void *pc) {
  return (((uint64_t)pc) >> 3) & hotmap_mask;
}
#define OP(code)                                                               \
  PRESERVE_NONE gc_obj impl_##code(bc *pc, gc_obj *stack, vm_state *state,     \
                                   void *op_table, uint8_t argcnt)

typedef struct {
  bc *pc;
  gc_obj *stack;
} frame_state;

static inline void *check_record_start(bc *pc, gc_obj *stack, vm_state *state,
                                       void *op_table) {
  uint8_t *hot_loc = &state->hotmap[hotmap_hash(pc)];
  uint8_t prev_hot = *hot_loc;
  *hot_loc -= 1;
  if ((state->max_trace > 0) && prev_hot < *hot_loc &&
      op_table == state->impls) {
    *hot_loc = hotmap_cnt;
    record_start(state, pc, stack);
    return state->record_impls;
  }
  return op_table;
}

static inline gc_obj stack_load(gc_obj *stack, uint8_t slot) {
  return stack[slot];
}
static inline void stack_save(gc_obj *stack, uint8_t slot, gc_obj res) {
  stack[slot] = res;
}
static inline gc_obj const_load(bc *pc, uint16_t offset) {
  return *(gc_obj *)(pc - pc->data);
}
static inline gc_obj emit_ov_math_add(gc_obj v1, gc_obj v2) {
  return tag_fixnum(to_fixnum(v1) + to_fixnum(v2));
}
static inline gc_obj emit_ov_math_sub(gc_obj v1, gc_obj v2) {
  return tag_fixnum(to_fixnum(v1) - to_fixnum(v2));
}
static inline gc_obj emit_math_cmp_lt(gc_obj v1, gc_obj v2) {
  return to_fixnum(v1) < to_fixnum(v2) ? TRUE_REP : FALSE_REP;
}
static inline void ensure_symbol(gc_obj val) { (void)val; }
static inline frame_state return_frame(bc *pc, gc_obj *stack) {
  auto ret = stack[pc->reg];
  auto new_pc = to_return_address(stack[-1]);
  auto old_pc = new_pc - 1;
  auto new_stack = stack - old_pc->reg - 1;
  new_stack[old_pc->reg] = ret;
  return (frame_state){.pc = new_pc, .stack = new_stack};
}
static inline bc *next_op(bc *pc) { return pc + 1; }
static inline gc_obj halt(gc_obj *stack) { return stack[0]; }

static inline gc_obj sym_load(gc_obj sym) { return to_symbol(sym)->val; }
static inline void prepare_call(gc_obj fun) {
  // TODO nothing?
}
static inline void check_arity(gc_obj fun, gc_obj args) {
  // TODO nothing for now
}
static inline bc *branch_if_false(bc *pc, gc_obj *stack, gc_obj b) {
  if (b.value == FALSE_REP.value) {
    return pc + pc->data;
  }
  return pc + 1;
}
static inline gc_obj closure_get(gc_obj clo, uint8_t slot) {
  return to_closure(clo)->v[slot];
}
static inline gc_obj return_address(bc *ra) { return tag_return_address(ra); }
static inline gc_obj *adjust_stack_depth(gc_obj *stack, int depth) {
  // TODO check stack depth?
  return stack + depth;
}
static inline bc *set_new_pc(bc *pc, gc_obj *stack, gc_obj func) {
  auto bfunc = to_func(func);
  return (bc *)(&bfunc->data[bfunc->const_cnt * sizeof(gc_obj)]);
}
static inline gc_obj constify_data(uint16_t data) {
  return (gc_obj){.value = data};
}

extern trace **traces;
static inline void *jit_func(bc **pc, gc_obj **stack, vm_state *state,
                             void *op_table) {
  (void)state;
  auto jfunc = (*pc)->data;
  // printf("RUN jit %i\n", jfunc);
  auto fn = traces[jfunc]->fn;
  auto res = fn(*stack);
  *pc = res.snap->pc;
  *stack = res.stack;
  // printf("RUN DONE jit %i\n", jfunc);
  return op_table;
}
#define dispatch_next(pc, stack)                                               \
  op_func impl = ((op_func *)op_table)[(pc)->op];                              \
  MUSTTAIL return impl(pc, stack, state, op_table, 0);

#include "vmgen.c"

#define X(name)                                                                \
  PRESERVE_NONE gc_obj record_##name(bc *pc, gc_obj *stack, vm_state *state,   \
                                     void *op_table, uint8_t argcnt);
OPS;
#undef X

static void vm_state_init(vm_state *state) {
  memset(state, 0, sizeof(*state));
  state->max_trace = 1;
#define X(name) state->impls[OP_##name] = impl_##name;
  OPS
#undef X
#define X(name) state->record_impls[OP_##name] = record_##name;
      OPS
#undef X
}

gc_obj vm(bc *pc) {
  gc_obj *stack = calloc(1024, sizeof(gc_obj));
  vm_state *state = calloc(1, sizeof(vm_state));

  return state->impls[pc->op](pc, stack, state, state->impls, 0);
}
