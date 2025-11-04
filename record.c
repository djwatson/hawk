#include "types.h"
#include "hawk.h"
#include "bc.h"
#include "ir.h"

// TODO merge type shit
typedef struct {
  bc *pc;
  gc_obj *stack;
} frame_state;

#define OP(code) PRESERVE_NONE gc_obj record_##code(bc *pc, gc_obj *stack, void* op_table, uint8_t argcnt)
typedef gc_obj PRESERVE_NONE (*op_func)(bc *pc, gc_obj *stack, void* op_table, uint8_t argcnt);
extern op_func impls[OP_INS_MAX];
extern op_func record_impls[OP_INS_MAX];
// end TODO

static inline slot stack_load(gc_obj* stack, uint8_t pos) { return (slot){.constant = false, .loc = 0}; }
static inline void stack_save(gc_obj* stack, uint8_t pos, slot res) {

}
static inline slot const_load(bc *pc, uint16_t offset) {
return (slot){.constant = false, .loc = 0}; 
}
static inline slot emit_ov_math_add(slot v1, slot v2) {
  return v1;
}
static inline slot emit_ov_math_sub(slot v1, slot v2) {
  return v1;
}
static inline slot emit_math_cmp_lt(slot v1, slot v2) {
  return v1;
}
static inline void ensure_symbol(slot val) {}
static inline slot constify_data(uint16_t data) {
  return (slot){};
}
static inline frame_state return_frame(bc *pc, gc_obj *stack) {
  return (frame_state){pc, stack};
}
static inline bc* next_op(bc *pc) {
  return pc;
}
static inline gc_obj halt(gc_obj *stack) {
  printf("DONE\n");
  return stack[0];
}

static inline slot sym_load(slot sym) {
  return (slot){.constant = false, .loc = 0};   
}
static inline void prepare_call(gc_obj fun) {
}
static inline void check_arity(gc_obj fun, gc_obj args) {
}
static inline bc* branch_if_false(bc* pc, slot b) {
  return pc;
}
static inline slot closure_get(slot clo, uint8_t pos) {
  return clo;
}
static inline slot return_address(bc * ra) {
  return (slot){};
}
static inline gc_obj* adjust_stack_depth(gc_obj * stack, int depth) {
  return stack;
}
static inline bc* set_new_pc(bc* pc, slot func) {
  return pc;
}
static inline bool check_record_start(void* pc) {
  return false;
}

// Tailcall to the non-recording version, which will then tailcall the
// next *recording* opcode
#define dispatch_next(pc, stack) \
  op_func impl = ((op_func*)impls)[pc->op];	\
  MUSTTAIL return impl(pc, stack, op_table, 0);

#include "vmgen.c"
