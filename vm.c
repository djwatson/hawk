// Copyright 2024 Dave Watson <dade.watson@gmail.com>
#define _DEFAULT_SOURCE

#include <assert.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "foreign.h"
#include "gc.h"
#include "ir.h"
#include "jitdump.h"
#include "profiler.h"
#include "runtime.h"
#include "vm.h"

static inline char const *func_name_for_pc(bc *pc);
static void debug_print_vm_backtrace(vm_state *state, bc *pc, gc_obj *stack);
static vm_state *current_vm_state;

#define VMGEN_TRACE_OP(pc, code, state, argcnt)                                \
  do {                                                                         \
    if (verbose) {                                                             \
    }                                                                          \
  } while (0)
enum : uint8_t {
  hotmap_sz = VM_HOTMAP_SZ,
  hotmap_loop = 3,
  hotmap_mask = (hotmap_sz - 1),
  hotmap_rec = 1,
  hotmap_cnt = 200,
  func_flag_rest = 1,
};
static bool should_jit() {
  static uint8_t next = 0;
  static bool initialized = false;
  if (!initialized) {
    next = (uint8_t)(random() % 256);
    initialized = true;
  }
  if (next-- == 0) {
    next = (uint8_t)(random() % 256);
    return true;
  }
  return false;
}
static inline uint32_t hotmap_hash(void *pc) {
  return (((uint64_t)pc) >> 3) & hotmap_mask;
}

static inline void *check_record_start(bc *pc, gc_obj *stack, vm_state *state,
                                       void *op_table, uint64_t argcnt) {
  uint8_t *hot_loc = &state->hotmap[hotmap_hash(pc)];
  uint8_t prev_hot = *hot_loc;
  *hot_loc -= 1;
  if ((state->max_trace > 0) &&
#ifdef RANDOM_SCHEDULE
      should_jit() &&
#else
      prev_hot < *hot_loc &&
#endif
      op_table == state->impls && state->record.cur_trace == nullptr &&
      (pc->op == OP_FUNC || pc->op == OP_LOOP || pc->op == OP_RET ||
       pc->op == OP_RETN)) {
    if (state->record.cur_trace != nullptr) {
      printf("Record while recording???\n");
      abort();
    }

    *hot_loc = hotmap_cnt;
    record_start(state, pc, *pc, stack, argcnt);
    return state->record_impls;
  }
  return op_table;
}

static inline gc_obj const_load(bc *pc, uint16_t offset) {
  return *(gc_obj *)(pc - pc->data);
}

static NOINLINE gc_obj emit_ov_math_add_slowpath(vm_state *state, bc *pc,
                                                 gc_obj *stack, gc_obj v1,
                                                 gc_obj v2) {
  (void)state;
  (void)pc;
  (void)stack;
  return vm_runtime_math_add_slow(v1, v2);
}

static NOINLINE gc_obj emit_ov_math_sub_slowpath(vm_state *state, bc *pc,
                                                 gc_obj *stack, gc_obj v1,
                                                 gc_obj v2) {
  (void)state;
  (void)pc;
  (void)stack;
  return vm_runtime_math_sub_slow(v1, v2);
}

static NOINLINE gc_obj emit_ov_math_mul_slowpath(vm_state *state, bc *pc,
                                                 gc_obj *stack, gc_obj v1,
                                                 gc_obj v2) {
  (void)state;
  (void)pc;
  (void)stack;
  return vm_runtime_math_mul_slow(v1, v2);
}

#define DEFINE_VM_FAST_OVERFLOW_MATH(name, oplcname, shift, slowpath)          \
  static inline gc_obj emit_ov_math_##name(                                    \
      vm_state *state, bc *pc, gc_obj *stack, gc_obj v1, gc_obj v2) {          \
    if (likely((is_fixnum(v1) & is_fixnum(v2)) == 1)) {                        \
      gc_obj res;                                                              \
      if (likely(!__builtin_##oplcname##_overflow(v1.value, shift(v2.value),   \
                                                  &res.value))) {              \
        return res;                                                            \
      }                                                                        \
    }                                                                          \
    MUSTTAIL return slowpath(state, pc, stack, v1, v2);                        \
  }

DEFINE_VM_FAST_OVERFLOW_MATH(add, add, VM_MATH_NOSHIFT,
                             emit_ov_math_add_slowpath)
DEFINE_VM_FAST_OVERFLOW_MATH(sub, sub, VM_MATH_NOSHIFT,
                             emit_ov_math_sub_slowpath)
DEFINE_VM_FAST_OVERFLOW_MATH(mul, mul, VM_MATH_SHIFT, emit_ov_math_mul_slowpath)

#undef DEFINE_VM_FAST_OVERFLOW_MATH

static inline gc_obj emit_ov_math_div(vm_state *state, gc_obj v1, gc_obj v2) {
  (void)state;
  return vm_runtime_math_div_slow(v1, v2);
}

static NOINLINE gc_obj emit_ov_math_quotient_slowpath(vm_state *state, bc *pc,
                                                      gc_obj *stack, gc_obj v1,
                                                      gc_obj v2) {
  (void)state;
  (void)pc;
  (void)stack;
  return vm_runtime_math_quotient_slow(v1, v2);
}

static NOINLINE gc_obj emit_ov_math_mod_slowpath(vm_state *state, bc *pc,
                                                 gc_obj *stack, gc_obj v1,
                                                 gc_obj v2) {
  (void)state;
  (void)pc;
  (void)stack;
  return vm_runtime_math_mod_slow(v1, v2);
}

static inline gc_obj emit_ov_math_quotient(vm_state *state, bc *pc,
                                           gc_obj *stack, gc_obj v1,
                                           gc_obj v2) {
  if (likely((is_fixnum(v1) & is_fixnum(v2)) == 1)) {
    if (unlikely(to_fixnum(v2) == 0)) {
      abort();
    }
    return tag_fixnum(to_fixnum(v1) / to_fixnum(v2));
  }
  MUSTTAIL return emit_ov_math_quotient_slowpath(state, pc, stack, v1, v2);
}

static inline gc_obj emit_ov_math_mod(vm_state *state, bc *pc, gc_obj *stack,
                                      gc_obj v1, gc_obj v2) {
  if (likely((is_fixnum(v1) & is_fixnum(v2)) == 1)) {
    if (unlikely(to_fixnum(v2) == 0)) {
      abort();
    }
    return tag_fixnum(to_fixnum(v1) % to_fixnum(v2));
  }
  MUSTTAIL return emit_ov_math_mod_slowpath(state, pc, stack, v1, v2);
}

#define DEFINE_VM_CMP_SLOW_STUB(name)                                          \
  static NOINLINE gc_obj emit_math_cmp_##name##_slowpath(                      \
      vm_state *state, bc *pc, gc_obj *stack, gc_obj v1, gc_obj v2) {          \
    (void)state;                                                               \
    (void)pc;                                                                  \
    (void)stack;                                                               \
    return vm_runtime_cmp_##name##_slow(v1, v2);                               \
  }

#define DEFINE_VM_FAST_CMP(name, op)                                           \
  static inline gc_obj emit_math_cmp_##name(                                   \
      vm_state *state, bc *pc, gc_obj *stack, gc_obj v1, gc_obj v2) {          \
    if (likely((is_fixnum(v1) & is_fixnum(v2)) == 1)) {                        \
      return to_fixnum(v1) op to_fixnum(v2) ? TRUE_REP : FALSE_REP;            \
    }                                                                          \
    MUSTTAIL return emit_math_cmp_##name##_slowpath(state, pc, stack, v1, v2); \
  }

DEFINE_VM_CMP_SLOW_STUB(lt)
DEFINE_VM_CMP_SLOW_STUB(gt)
DEFINE_VM_CMP_SLOW_STUB(lte)
DEFINE_VM_CMP_SLOW_STUB(gte)

DEFINE_VM_FAST_CMP(lt, <)
DEFINE_VM_FAST_CMP(gt, >)
DEFINE_VM_FAST_CMP(lte, <=)
DEFINE_VM_FAST_CMP(gte, >=)

#undef DEFINE_VM_FAST_CMP
#undef DEFINE_VM_CMP_SLOW_STUB

static inline gc_obj emit_math_cmp_jeq(vm_state *state, bc *pc, gc_obj *stack,
                                       gc_obj v1, gc_obj v2) {
  (void)state;
  (void)pc;
  (void)stack;
  return v1.value == v2.value ? TRUE_REP : FALSE_REP;
}
static NOINLINE gc_obj emit_math_cmp_jeqv_slowpath(vm_state *state, bc *pc,
                                                   gc_obj *stack, gc_obj v1,
                                                   gc_obj v2) {
  (void)state;
  (void)pc;
  (void)stack;
  return vm_runtime_cmp_jeqv_slow(v1, v2);
}

static inline gc_obj emit_math_cmp_jeqv(vm_state *state, bc *pc, gc_obj *stack,
                                        gc_obj v1, gc_obj v2) {
  if (likely((is_fixnum(v1) & is_fixnum(v2)) == 1)) {
    return to_fixnum(v1) == to_fixnum(v2) ? TRUE_REP : FALSE_REP;
  }
  MUSTTAIL return emit_math_cmp_jeqv_slowpath(state, pc, stack, v1, v2);
}

gc_obj vm_memq(gc_obj obj, gc_obj list) {
  for (auto cur = list; is_cons(cur); cur = to_cons(cur)->b) {
    if (obj.value == to_cons(cur)->a.value) {
      return cur;
    }
  }
  return FALSE_REP;
}

gc_obj vm_memv(gc_obj obj, gc_obj list) {
  for (auto cur = list; is_cons(cur); cur = to_cons(cur)->b) {
    if (obj_jeqv(obj, to_cons(cur)->a)) {
      return cur;
    }
  }
  return FALSE_REP;
}

static void trace_reset(vm_state *state) {
  arr_for_each(state->record.traces, trace) {
    if (!trace->parent_snap && trace->start_ins &&
        (trace->start_ins->op == OP_JFUNC ||
         trace->start_ins->op == OP_JLOOP)) {
      *trace->start_ins = trace->start_pc;
    }
  }
  arr_for_each(state->record.penalty_pcs, pc) {
    if (pc->op == OP_IFUNC) {
      pc->op = OP_FUNC;
    } else if (pc->op == OP_ILOOP) {
      pc->op = OP_LOOP;
    } else if (pc->op == OP_IRET) {
      pc->op = OP_RET;
    }
  }
  free_traces(state);
  emit_cleanup(&state->emit);
  emit_init(&state->emit);
  record_init(&state->record);
  memset(state->hotmap, hotmap_cnt, sizeof(state->hotmap));
}

EXPORT void vm_trace_reset(void) {
  if (!current_vm_state) {
    abort();
  }
  if (current_vm_state->record.cur_trace) {
    current_vm_state->record.reset_pending = true;
    return;
  }
  trace_reset(current_vm_state);
}
static inline void return_frame(vm_state *state, bc instr, uint16_t count,
                                bc **pc, gc_obj **stack, void **op_table) {
  (void)state;
  (void)op_table;
  auto new_pc = to_return_address((*stack)[-1]);
  auto old_pc = new_pc - 1;
  auto new_stack = *stack - old_pc->reg - 1;
  if (count > 0) {
    memmove(&new_stack[old_pc->reg], &(*stack)[instr.reg],
            (size_t)count * sizeof(gc_obj));
  }
  *pc = new_pc;
  *stack = new_stack;
}
static inline bc *next_op(bc *pc) { return pc + 1; }

static bc callcc_resume_stub[] = {
    {.op = OP_LCALL, .reg = 1, .data = 3},
    {.op = OP_CALLCC_RESUME, .reg = 0},
};

static bc vm_entry_stub[] = {
    {.op = OP_LCALL, .reg = 0, .data = 2},
    {.op = OP_HALT, .reg = 0},
};

static struct {
  gc_header header;
  gc_obj name;
  uint64_t const_cnt;
  uint64_t bc_cnt;
  bc code[1];
} callcc_resume_func = {
    .header = {.type = FUNC_TAG},
    .name = UNDEFINED,
    .const_cnt = 0,
    .bc_cnt = 1,
    .code = {{.op = OP_CALLCC_RESUME, .reg = 0}},
};

gc_obj vm_callcc_resume_func_obj(void) {
  return tag_func((bcfunc *)&callcc_resume_func);
}

static inline gc_obj capture_stack_closure(vm_state *state, gc_obj *stack) {
  ptrdiff_t saved_len = stack - state->stack_bottom;
  if (saved_len < 0) {
    abort();
  }
  size_t words = (size_t)saved_len;
  size_t payload_words = words + 1;
  size_t bytes = sizeof(closure_s) + (sizeof(gc_obj) * payload_words);
  closure_s *captured = gc_alloc(bytes);
  captured->header.type = CLOSURE_TAG;
  captured->len = tag_fixnum((int64_t)payload_words);
  captured->v[0] = vm_callcc_resume_func_obj();
  memcpy(&captured->v[1], state->stack_bottom, sizeof(gc_obj) * words);
  return tag_closure(captured);
}

static inline void call_with_captured_stack(bc **pc, gc_obj **stack,
                                            gc_obj callcc_arg,
                                            gc_obj captured_stack,
                                            uint64_t *argcnt) {
  if (!is_closure(callcc_arg)) {
    abort();
  }
  auto clo = to_closure(callcc_arg);
  auto func = clo->v[0];
  if (!is_func(func)) {
    abort();
  }
  gc_obj *base = *stack;
  base[0] = captured_stack;
  base[1] = tag_return_address(&callcc_resume_stub[1]);
  gc_obj *callee_stack = base + 2;
  callee_stack[0] = callcc_arg;
  callee_stack[1] = captured_stack;
  *argcnt = 2;
  *stack = callee_stack;
  auto bfunc = to_func(func);
  *pc = (bc *)(&bfunc->data[bfunc->const_cnt * sizeof(gc_obj)]);
}

vm_callcc_result vm_callcc_slow(vm_state *state, gc_obj *stack,
                                gc_obj callcc_arg) {
  gc_add_root((const void *)&callcc_arg, 1, 0);
  gc_obj captured_stack = capture_stack_closure(state, stack);
  gc_remove_root((const void *)&callcc_arg, 0);
  bc *pc = nullptr;
  uint64_t argcnt = 0;
  stack = state->stack_bottom;
  call_with_captured_stack(&pc, &stack, callcc_arg, captured_stack, &argcnt);
  return (vm_callcc_result){.value = captured_stack, .stack = stack};
}

gc_obj *vm_callcc_resume_slow(vm_state *state, gc_obj captured) {
  auto clo = to_closure(captured);
  size_t saved_words = (size_t)(to_fixnum(clo->len) - 1);
  gc_obj *restored_top = state->stack_bottom + saved_words;
  while (restored_top >= state->stack_limit) {
    restored_top = expand_stack(state, restored_top);
  }
  memcpy(state->stack_bottom, &clo->v[1], sizeof(gc_obj) * saved_words);
  return restored_top;
}

gc_obj halt(vm_state *state, gc_obj *stack) {
  profiler_stop();
  jit_dump_close();
  if (verbose) {
    size_t up_recursive_traces = 0;
    size_t ret_traces = 0;
    size_t side_traces = 0;
    size_t normal_loop_traces = 0;
    auto traces = state->record.traces;
    arr_for_each_idx(traces, i) {
      auto t = traces[i];
      if (t->parent_snap != nullptr) {
        side_traces++;
        continue;
      }
      if (t->start_pc.op == OP_RET || t->start_pc.op == OP_IRET) {
        ret_traces++;
        continue;
      }
      if (t->start_pc.op == OP_FUNC || t->start_pc.op == OP_IFUNC) {
        bool last_snap_has_offset = false;
        if (arrlen(t->snaps) > 0) {
          auto last_snap = &t->snaps[arrlen(t->snaps) - 1];
          last_snap_has_offset = last_snap->offset != 0;
        }
        if (last_snap_has_offset) {
          up_recursive_traces++;
        } else {
          normal_loop_traces++;
        }
        continue;
      }
      if (t->start_pc.op == OP_LOOP || t->start_pc.op == OP_ILOOP) {
        normal_loop_traces++;
      }
    }
    printf("Trace counts (%li total):\n", (long)arrlen(traces));
    printf("  up-recursive: %li\n", (long)up_recursive_traces);
    printf("  down-recursive: %li\n", (long)ret_traces);
    printf("  normal-loop: %li\n", (long)normal_loop_traces);
    printf("  side: %li\n", (long)side_traces);
  }
  auto res = stack[0];
  free_traces(state);
  gc_remove_root((const void *)state->stack_bottom, 0);
  emit_cleanup(&state->emit);
  gc_free();
  free(state->stack_bottom);
  free(state);
  return res;
}
static inline void fail_if_not_closure(vm_state *state, bc *pc, gc_obj *stack,
                                       gc_obj clo) {
  if (!is_closure(clo)) {
    printf("Attempting to call a non-closure:");
    print_obj(clo, stdout);
    printf("\n");
    debug_print_vm_backtrace(state, pc, stack);
    abort();
  }
}
gc_obj *expand_stack(vm_state *state, gc_obj *stack) {
  // TODO: this should really be a stack *cache*
  size_t oldsz = (size_t)(state->stack_top - state->stack_bottom);
  size_t newsz = oldsz + (oldsz / 3);
  size_t grow = newsz - oldsz;
  if (newsz <= oldsz) {
    newsz = oldsz + 1;
    grow = 1;
  }
  gc_obj *old_bottom = state->stack_bottom;
  auto offset = stack - state->stack_bottom;
  if (verbose) {
    printf("MUST EXPAND STACK now %li\n", newsz);
  }
  gc_remove_root((const void *)old_bottom, 0);
  gc_obj *newstack = realloc(state->stack_bottom, sizeof(gc_obj) * newsz);
  if (!newstack) {
    fprintf(stderr, "Failed to realloc stack\n");
    abort();
  }
  memset(&newstack[oldsz], 0, grow * sizeof(gc_obj));
  state->stack_bottom = newstack;
  state->stack_top = newstack + newsz;
  state->stack_limit = state->stack_top - STACK_GUARD_SLOTS;
  // Potential improvement: the GC could callback to get the current stack size.
  // (or rather, stack + 256 redzone).
  // If the stack grew large but then stayed small, GC time would be improved.
  gc_add_root((const void *)state->stack_bottom, newsz, 0);
  return &newstack[offset];
}

static inline void check_expand_stack(vm_state *state, gc_obj **stack) {
  if (*stack >= state->stack_limit) {
    *stack = expand_stack(state, *stack);
  }
}
static inline bc *func_body_pc(bc *pc) {
  auto next = next_op(pc);
  return next_op(next);
}
static void build_list(uint8_t start, uint8_t len, gc_obj *stack) {
  gc_obj lst = NIL;
  gc_add_root((const void *)&lst, 1, 0);
  for (int i = (int)start + (int)len - 1; i >= (int)start; i--) {
    cons_s *c = gc_alloc(sizeof(cons_s));
    c->header.type = CONS_TAG;
    c->a = stack[i];
    c->b = lst;
    lst = tag_cons(c);
  }
  gc_remove_root((const void *)&lst, 0);
  stack[start] = lst;
}
static inline char const *func_name_for_pc(bc *pc) {
  bcfunc *func = gc_base_ptr(pc);
  if (!func || !is_ptr(func->name) || get_ptr_tag(func->name) != STRING_TAG) {
    return "(unknown func)";
  }
  return to_string(func->name)->str;
}

static void debug_print_vm_backtrace(vm_state *state, bc *pc, gc_obj *stack) {
  printf("VM backtrace:\n");
  for (int depth = 0; depth < 256; depth++) {
    printf("  #%d %s\n", depth, func_name_for_pc(pc));
    if (stack <= state->stack_bottom) {
      return;
    }

    auto ret_pc = to_return_address(stack[-1]);
    if (!ret_pc) {
      return;
    }

    auto call_pc = ret_pc - 1;
    auto caller_stack = stack - call_pc->reg - 1;
    if (caller_stack < state->stack_bottom || caller_stack >= stack) {
      return;
    }

    pc = ret_pc;
    stack = caller_stack;
  }
  printf("  ... (truncated)\n");
}

static inline bool check_arity(vm_state *state, gc_obj *stack, bc *pc, bc instr,
                               uint64_t *args, bool abort_on_fail) {
  (void)state;
  bool has_rest = (instr.v1 & func_flag_rest) != 0;
  if (!has_rest) {
    if (*args == instr.reg) {
      return true;
    }
    if (abort_on_fail) {
      printf("Bad argcnt in %s expected %i got %lu\n", func_name_for_pc(pc),
             instr.reg, *args);
      debug_print_vm_backtrace(state, pc, stack);
      abort();
    }
    return false;
  }

  uint8_t fixed_cnt = instr.reg - 1;
  if (*args < fixed_cnt) {
    if (abort_on_fail) {
      printf("Bad argcnt in %s expected %i+ got %lu\n", func_name_for_pc(pc),
             fixed_cnt, *args);
      debug_print_vm_backtrace(state, pc, stack);
      abort();
    }
    return false;
  }
  build_list(fixed_cnt, *args - fixed_cnt, stack);
  *args = instr.reg;
  return true;
}
static inline bc *set_new_pc(vm_state *state, bc *pc, gc_obj *stack,
                             gc_obj func) {
  (void)state;
  (void)pc;
  (void)stack;
  if (is_closure(func)) {
    func = to_closure(func)->v[0];
  }
  auto bfunc = to_func(func);
  return (bc *)(&bfunc->data[bfunc->const_cnt * sizeof(gc_obj)]);
}

static inline void *jit_func(bc *instr, bc **pc, gc_obj **stack,
                             vm_state *state, void *op_table,
                             uint64_t *argcnt) {
  auto jfunc = (*pc)->data;
  auto traces = state->record.traces;
  auto trace = traces[jfunc];
  auto fn = trace->fn;
  profiler_set_in_jit(true);
  auto res = fn(state, *stack);
  profiler_set_in_jit(false);
  *pc = res.snap->pc;
  *instr = **pc;
  *stack = res.stack;
  *argcnt = res.snap->argcnt;
  // printf("Exit trace %i snap ir %i\n", res.snap->trace->num, res.snap->ir);

  // If we're exiting to a JFUNC, it means we've failed some check at
  // the start of a trace (otherwise we would have linked to it). Run
  // the code in the VM instead.
  if ((*pc)->op == OP_JFUNC || (*pc)->op == OP_JLOOP) {
    auto trace = traces[(*pc)->data];
    *instr = trace->start_pc;
    assert(instr->op != OP_JFUNC && instr->op != OP_JLOOP);
  }
  // Check for side trace start.
  if (res.snap->exits < 255) {
    bool should_try_side = false;
#ifdef RANDOM_SCHEDULE
    if (should_jit() && state->max_trace > 0) {
      should_try_side = true;
      res.snap->exits++;
    }
#else
    res.snap->exits++;
    if (res.snap->exits >= 10 && res.snap->exits % 10 == 0 &&
        state->max_trace > 0) {
      should_try_side = true;
    }
#endif
    if (res.snap->exits == 255) {
      if (verbose) {
        printf("Blacklist side trace %i snap %i \n", res.snap->trace->num,
               res.snap->ir);
      }
    }
    if (should_try_side) {
      auto parent = res.snap->trace;
      bool is_poly_trace =
          res.snap == &parent->snaps[0] && parent->kind != TRACE_SIDE;
      if (verbose) {
        printf("Try side trace %i %i\n", res.snap->trace->num, res.snap->ir);
      }
      if (is_poly_trace) {
        record_start_poly(state, *pc, *instr, *stack, res.snap, *argcnt);
      } else {
        record_start_side(state, *pc, *instr, *stack, res.snap, *argcnt);
      }
      return state->record_impls;
    }
  }

  // printf("RUN DONE jit %i\n", jfunc);
  return op_table;
}
#define dispatch_next(pc, stack)                                               \
  op_func impl = ((op_func *)op_table)[(pc)->op];                              \
  MUSTTAIL return impl(*(pc), (pc), (stack), state, op_table, argcnt);

#define OP(code)                                                               \
  PRESERVE_NONE gc_obj impl_##code(bc instr, bc *pc, gc_obj *stack,            \
                                   vm_state *state, void *op_table,            \
                                   uint64_t argcnt) {
#define END }
#define OP_ABC(code)                                                           \
  OP(code)                                                                     \
  auto v1 = stack[instr.v1];                                                   \
  auto v2 = stack[instr.v2];
#define OP_AD(code)                                                            \
  OP(code)                                                                     \
  auto v1 = stack[instr.data];
#define END_ABC_NEXT                                                           \
  stack[instr.reg] = res;                                                      \
  pc = next_op(pc);                                                            \
  dispatch_next(pc, stack);                                                    \
  END
#define END_NEXT                                                               \
  pc = next_op(pc);                                                            \
  dispatch_next(pc, stack);                                                    \
  END

// Begin opcode handlers.
OP_ABC(ADD) {
  auto res = emit_ov_math_add(state, pc, stack, v1, v2);
  END_ABC_NEXT
}
OP_ABC(SUB) {
  auto res = emit_ov_math_sub(state, pc, stack, v1, v2);
  END_ABC_NEXT
}
OP_ABC(MUL) {
  auto res = emit_ov_math_mul(state, pc, stack, v1, v2);
  END_ABC_NEXT
}
OP_ABC(DIV) {
  auto res = emit_ov_math_div(state, v1, v2);
  END_ABC_NEXT
}
OP_ABC(QUOTIENT) {
  auto res = emit_ov_math_quotient(state, pc, stack, v1, v2);
  END_ABC_NEXT
}
OP_ABC(MOD) {
  auto res = emit_ov_math_mod(state, pc, stack, v1, v2);
  END_ABC_NEXT
}
OP_ABC(MEMQ) {
  auto res = vm_memq(v1, v2);
  END_ABC_NEXT
}
OP_ABC(MEMV) {
  auto res = vm_memv(v1, v2);
  END_ABC_NEXT
}
OP_AD(INEXACT) {
  auto res = numeric_inexact_value(v1);
  END_ABC_NEXT
}
OP_AD(EXACT) {
  auto res = numeric_exact_value(v1);
  END_ABC_NEXT
}
OP_AD(TRUNCATE) {
  auto res = numeric_truncate_value(v1);
  END_ABC_NEXT
}
OP(CONST) {
  auto res = const_load(pc, instr.data);
  END_ABC_NEXT
}
OP(KSHORT) {
  auto res = (gc_obj){.value = (int16_t)instr.data};
  END_ABC_NEXT
}
OP_AD(MOV) {
  auto res = v1;
  END_ABC_NEXT
}
OP(RET) {
  argcnt = 1;
  // TODO: re-enable.  This needs to be a MUCH lower priority, so we
  // don't record down-rec before up-rec.  Or alternatively, maybe
  // ONLY enable down-rec recording if the function has an up-rec trace already.

  /* auto res = check_record_start(pc, stack, state, op_table); */
  /* if (res != op_table) { */
  /*   op_table = res; */
  /*   instr = *pc; */
  /*   dispatch_next(pc, stack); */
  /* } */

  auto old_op_table = op_table;
  return_frame(state, instr, 1, &pc, &stack, &op_table);
  if (old_op_table != op_table) {
    instr = *pc;
  }
  dispatch_next(pc, stack);
  END
}
OP(IRET) {
  argcnt = 1;
  auto old_op_table = op_table;
  return_frame(state, instr, 1, &pc, &stack, &op_table);
  if (old_op_table != op_table) {
    instr = *pc;
  }
  dispatch_next(pc, stack);
  END
}
OP(RETN) {
  argcnt = instr.data;
  auto old_op_table = op_table;
  return_frame(state, instr, instr.data, &pc, &stack, &op_table);
  if (old_op_table != op_table) {
    instr = *pc;
  }
  dispatch_next(pc, stack);
  END
}
OP(LOOKUP) {
  auto sym = const_load(pc, instr.data);
  // No need to check if c is a symbol, the compiler guarantees it
  auto s = to_symbol(sym);
  auto res = s->val;
  if (res.value == DEAD.value) {
    auto name = get_sym_name(s);
    printf("Symbol not defined: %.*s\n", (int)to_fixnum(name->len), name->str);
    debug_print_vm_backtrace(state, pc, stack);
    abort();
  }
  END_ABC_NEXT
}

OP(DEFINE) {
  auto sym = const_load(pc, instr.data);
  auto val = stack[instr.reg];
  auto s = to_symbol(sym);
  if (s->opt > 0) {
    if (true || verbose) {
      printf("Clearing trace cache due to optimistic global: %s\n",
             to_string(s->name)->str);
    }
    trace_reset(state);
    op_table = state->impls;
  }
  if (s->val.value != DEAD.value) {
    // If we've set this more than once, mark it as non-inlinable.
    s->opt = -1;
  }
  s->val = val;
  END_NEXT
}

OP(WRITE) {
  auto val = stack[instr.v1];
  print_obj(val, stdout);
  END_NEXT
}

OP(FUNC) {
  if (!check_arity(state, stack, pc, instr, &argcnt, false)) {
    pc = next_op(pc);
    dispatch_next(pc, stack);
  }

  check_expand_stack(state, &stack);
  auto old_ops = op_table;
  op_table = check_record_start(pc, stack, state, op_table, argcnt);
  if (op_table != old_ops) {
    instr = *pc;
  }

  pc = func_body_pc(pc);
  dispatch_next(pc, stack);
  END
}

OP(ARGCNT_ERROR) {
  check_arity(state, stack, pc, instr, &argcnt, true);
  END_NEXT
}

OP(IFUNC) {
  if (!check_arity(state, stack, pc, instr, &argcnt, false)) {
    pc = next_op(pc);
    dispatch_next(pc, stack);
  }

  check_expand_stack(state, &stack);
  pc = func_body_pc(pc);
  dispatch_next(pc, stack);
  END
}

OP(ILOOP) {
  END_NEXT
}

OP(JFUNC) {
  auto trace = state->record.traces[instr.data];
  auto start = trace->start_pc;
  if (start.op == OP_FUNC &&
      !check_arity(state, stack, pc, start, &argcnt, false)) {
    pc = next_op(pc);
    dispatch_next(pc, stack);
  }
  if (start.op == OP_IFUNC) {
    check_arity(state, stack, pc, start, &argcnt, true);
  }
  op_table = jit_func(&instr, &pc, &stack, state, op_table, &argcnt);

  /* if ((*pc).op != instr.op) { */
  /*   abort(); */
  /* } */
  op_func impl = ((op_func *)op_table)[instr.op];
  MUSTTAIL return impl(instr, pc, stack, state, op_table, argcnt);
  END
}

OP(JLOOP) {
  op_table = jit_func(&instr, &pc, &stack, state, op_table, &argcnt);
  op_func impl = ((op_func *)op_table)[instr.op];
  MUSTTAIL return impl(instr, pc, stack, state, op_table, argcnt);
  END
}
#define BRANCH_NEXT(COND)                                                      \
  do {                                                                         \
    auto jmp_pc = pc + 1;                                                      \
    pc = (COND) ? jmp_pc + 1 : jmp_pc + (int16_t)jmp_pc->data;                 \
  } while (0)

#define CMP_BRANCH(OPNAME, EMIT_FN)                                            \
  OP_ABC(OPNAME) {                                                             \
    auto res = EMIT_FN(state, pc, stack, v1, v2);                              \
    BRANCH_NEXT(res.value != FALSE_REP.value);                                 \
    dispatch_next(pc, stack);                                                  \
    END                                                                        \
  }

CMP_BRANCH(JLT, emit_math_cmp_lt)
CMP_BRANCH(JGT, emit_math_cmp_gt)
CMP_BRANCH(JLTE, emit_math_cmp_lte)
CMP_BRANCH(JGTE, emit_math_cmp_gte)
CMP_BRANCH(JEQ, emit_math_cmp_jeq)
CMP_BRANCH(JEQV, emit_math_cmp_jeqv)
OP(IF) {
  auto v = stack[instr.data];
  BRANCH_NEXT(v.value != FALSE_REP.value);
  dispatch_next(pc, stack);
  END
}
OP(JMP) {
  pc += (int16_t)pc->data;
  dispatch_next(pc, stack);
  END
}

OP_ABC(CLOSURE_GET) {
  fail_if_not_closure(state, pc, stack, v1);
  auto slot = instr.v2;
  auto res = to_closure(v1)->v[slot];
  END_ABC_NEXT
}

OP(CLOSURE_SET) {
  auto val = stack[instr.reg];
  auto clo = stack[instr.v1];
  auto slot = instr.v2;
  to_closure(clo)->v[slot] = val;
  END_NEXT
}

OP(CLOSURE) {
  uint64_t sz = (uint64_t)pc->data + 1;
  uint8_t start = pc->reg;
  size_t bytes = sizeof(closure_s) + (sizeof(gc_obj) * sz);
  closure_s *clo = gc_alloc(bytes);
  // Current closure algorithm requires zero-initilizing the whole
  // closure: since letrec* groups may reference each other,
  // we need to allocate all closures before assigning pointers.
  memset(clo, 0, bytes);
  clo->header.type = CLOSURE_TAG;
  clo->len = tag_fixnum((int64_t)sz);
  // Only seed slot 0 with the function label; closure captures are
  // initialized via explicit CLOSURE_SET bytecodes.
  clo->v[0] = stack[start];
  auto alloced = tag_closure(clo);
  stack[instr.reg] = alloced;
  END_NEXT
}

OP(LOOP) {
  auto old_ops = op_table;
  op_table = check_record_start(pc, stack, state, op_table, argcnt);
  if (op_table == old_ops) {
    state->hotmap[hotmap_hash(pc)] -= (hotmap_loop - 1);
  }
  END_NEXT
}

OP(LCALL) {
  argcnt = instr.data - 1;
  auto func = stack[instr.reg];
  auto frame_top = instr.reg;
  stack[instr.reg] = tag_return_address(pc + 1);
  stack += frame_top + 1;
  pc = set_new_pc(state, pc, stack, func);
  dispatch_next(pc, stack);
  END
}
OP(LCALLT) {
  argcnt = instr.data - 1;
  auto func = stack[instr.reg];
  auto frame_top = instr.reg;
  memmove(&stack[0], &stack[frame_top + 1], argcnt * sizeof(gc_obj));
  pc = set_new_pc(state, pc, stack, func);
  dispatch_next(pc, stack);
  END
}
OP(LCALL_N) {
  auto func = stack[instr.reg];
  stack[instr.reg] = tag_return_address(pc + 1);
  stack += instr.reg + 1;
  argcnt += 1;
  pc = set_new_pc(state, pc, stack, func);
  dispatch_next(pc, stack);
  END
}
OP(LCALLT_N) {
  auto func = stack[instr.reg];
  auto frame_top = instr.reg;
  memmove(&stack[0], &stack[frame_top + 1],
          (size_t)(argcnt + 1) * sizeof(gc_obj));
  argcnt += 1;
  pc = set_new_pc(state, pc, stack, func);
  dispatch_next(pc, stack);
  END
}
OP(APPLY) {
  auto fun = stack[pc->v1];
  auto args = stack[pc->v2];
  fail_if_not_closure(state, pc, stack, fun);
  auto callee = to_func(to_closure(fun)->v[0]);

  uint64_t a = 1;
  for (; is_cons(args); a++) {
    auto cons = to_cons(args);
    stack[a] = cons->a;
    args = cons->b;
  }
  stack[0] = fun;
  argcnt = a;
  pc = (bc *)(&callee->data[callee->const_cnt * sizeof(gc_obj)]);
  dispatch_next(pc, stack);
  END
}
OP(FOREIGN_CALL) {
  auto base = instr.v1;
  auto count = instr.v2;
  if (count < 1) {
    abort();
  }
  auto res =
      do_foreign_call(stack[base], &stack[base + 1], (uint8_t)(count - 1));
  stack[instr.reg] = res;
  END_NEXT
}
OP(ALLOC) {
  auto sz_obj = stack[pc->v1];
  auto type_obj = stack[pc->v2];
  assert(is_fixnum(sz_obj));
  assert(is_fixnum(type_obj));
  uint64_t sz = (uint64_t)to_fixnum(sz_obj);
  uint64_t type = (uint64_t)to_fixnum(type_obj);
  assert((sz & 0x7) == 0);

  auto obj = (gc_header *)gc_alloc(sz);
  if (type == VECTOR_TAG || type == RECORD_TAG) {
    memset((uint8_t *)obj + sizeof(gc_header), 0, (size_t)sz - sizeof(gc_header));
  }
  obj->type = type;
  if (type == SYMBOL_TAG) {
    ((symbol *)obj)->val = DEAD;
  }
  auto ptr =
      type < 8 ? tag_header(obj, (uint8_t)type) : tag_header(obj, PTR_TAG);
  stack[instr.reg] = ptr;
  END_NEXT
}

OP(STORE) {
  auto dest = stack[pc->reg];
  auto val = stack[pc->v1];
  auto off = stack[pc->v2];
  assert(is_heap_object(dest));
  assert(is_fixnum(off));

  auto base = (gc_obj *)((uint8_t *)to_raw_ptr(dest) + sizeof(gc_header));
  base[to_fixnum(off)] = val;
  END_NEXT
}
OP(STORE_CHAR) {
  auto dest = stack[pc->reg];
  auto val = stack[pc->v1];
  auto off = stack[pc->v2];
  assert(is_string(dest));
  assert(is_char(val));
  assert(is_fixnum(off));

  auto str = to_string(dest);
  auto idx = to_fixnum(off);
  auto len = to_fixnum(str->len);
  // TODO <= so we can store NULL-terminator.
  assert(idx >= 0 && idx <= len);
  str->str[idx] = to_char(val);
  END_NEXT
}

OP(GUARD) {
  auto val = stack[pc->v1];
  auto want_tag_obj = stack[pc->v2];

  auto res = guard_obj_matches(val, want_tag_obj) ? TRUE_REP : FALSE_REP;
  stack[instr.reg] = res;
  END_NEXT
}

OP(LOAD) {
  auto src = stack[pc->v1];
  auto off = stack[pc->v2];
  assert(is_heap_object(src));
  if (!is_fixnum(off)) {
    debug_print_vm_backtrace(state, pc, stack);
  }
  assert(is_fixnum(off));

  auto base = (gc_obj *)((uint8_t *)to_raw_ptr(src) + sizeof(gc_header));
  auto res = base[to_fixnum(off)];
  stack[instr.reg] = res;
  END_NEXT
}

OP(LOAD_CHAR) {
  auto src = stack[pc->v1];
  auto off = stack[pc->v2];
  assert(is_string(src));
  assert(is_fixnum(off));

  auto str = to_string(src);
  auto idx = to_fixnum(off);
  auto len = to_fixnum(str->len);
  assert(idx >= 0 && idx < len);
  auto res = tag_char((uint8_t)str->str[idx]);
  stack[instr.reg] = res;
  END_NEXT
}

OP_AD(CHAR_INTEGER) {
  assert(is_char(v1));
  auto c = to_char(v1);
  auto res = tag_fixnum(c);
  END_ABC_NEXT
}

OP_AD(INTEGER_CHAR) {
  assert(is_fixnum(v1));
  auto fix = to_fixnum(v1);
  auto res = tag_char(fix);
  END_ABC_NEXT
}

OP_AD(CALLCC) {
  auto captured_stack = capture_stack_closure(state, stack);
  // capture_stack_closure may relocate v1.
  v1 = stack[instr.data];
  stack[instr.reg] = captured_stack;
  stack = state->stack_bottom;
  call_with_captured_stack(&pc, &stack, v1, captured_stack, &argcnt);
  dispatch_next(pc, stack);
  END
}

OP(CALLCC_RESUME) {
  auto captured = stack[0];
  auto result = stack[1];
  if (!is_closure(captured)) {
    abort();
  }
  auto clo = to_closure(captured);
  auto len = to_fixnum(clo->len);
  if (len < 1) {
    abort();
  }
  if (clo->v[0].value != vm_callcc_resume_func_obj().value) {
    abort();
  }

  gc_obj *restored_top = vm_callcc_resume_slow(state, captured);

  auto new_pc = to_return_address(restored_top[-1]);
  auto old_pc = new_pc - 1;
  auto new_stack = restored_top - old_pc->reg - 1;
  new_stack[old_pc->reg] = result;
  pc = new_pc;
  stack = new_stack;
  dispatch_next(pc, stack);
  END
}

OP(HALT) {
  return halt(state, stack);
  END
}

// End opcode handlers.

static void vm_state_init(vm_state *state) {
  memset(state, 0, sizeof(*state));
  for (int i = 0; i < VM_HOTMAP_SZ; i++) {
    state->hotmap[i] = hotmap_cnt;
  }
  state->max_trace = max_trace;

  if (jit_dump_flag) {
    jit_dump_init();
  }

  record_init(&state->record);
  emit_init(&state->emit);
#define X(name, type) state->impls[OP_##name] = impl_##name;
  OPS
#undef X
      for (int i = 0; i < OP_INS_MAX; i++) {
    state->record_impls[i] = record;
  }
}

gc_obj vm(bcfunc *func, gc_obj arg1) {
  size_t default_size = 1024;
  vm_state *state = calloc(1, sizeof(vm_state));
  vm_state_init(state);
  current_vm_state = state;

  gc_obj *stack = calloc(default_size, sizeof(gc_obj));
  if (!stack) {
    fprintf(stderr, "Failed to allocate VM stack\n");
    exit(EXIT_FAILURE);
  }
  state->stack_bottom = stack;
  state->stack_top = stack + default_size;
  state->stack_limit = state->stack_top - STACK_GUARD_SLOTS;
  gc_add_root((const void *)state->stack_bottom, default_size, 0);
  if (profile) {
    profiler_start();
  }

  stack[0] = tag_func(func);
  bc *pc = vm_entry_stub;
  uint64_t argcnt = 1;
  if (!is_undefined(arg1)) {
    stack[2] = arg1;
    vm_entry_stub[0].data++;
  }

  return state->impls[pc->op](*pc, pc, stack, state, state->impls, 1);
}
