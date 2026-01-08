// Copyright 2024 Dave Watson <dade.watson@gmail.com>
#define _DEFAULT_SOURCE

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gc.h"
#include "ir.h"
#include "jitdump.h"
#include "profiler.h"
#include "vm.h"
#include "vm_guard.h"

#define VMGEN_TRACE_OP(pc, code, state)                                        \
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
};
static bool should_jit() {
  static uint8_t next = 0;
  if (next-- == 0) {
    next = random() % 256;
    return true;
  }
  return false;
}
static inline uint32_t hotmap_hash(void *pc) {
  return (((uint64_t)pc) >> 3) & hotmap_mask;
}
#define OP(code)                                                               \
  PRESERVE_NONE gc_obj impl_##code(bc instr, bc *pc, gc_obj *stack,            \
                                   vm_state *state, void *op_table,            \
                                   uint8_t argcnt)

static inline void *check_record_start(bc *pc, gc_obj *stack, vm_state *state,
                                       void *op_table) {
  uint8_t *hot_loc = &state->hotmap[hotmap_hash(pc)];
  uint8_t prev_hot = *hot_loc;
  *hot_loc -= 1;
  if ((state->max_trace > 0) &&
#ifdef RANDOM_SCHEDULE
      should_jit() &&
#else
      prev_hot < *hot_loc &&
#endif
      op_table == state->impls) {
    *hot_loc = hotmap_cnt;
    record_start(state, pc, *pc, stack, nullptr);
    return state->record_impls;
  }
  return op_table;
}

static inline gc_obj stack_load(vm_state *state, gc_obj *stack, uint8_t slot,
                                bool typecheck) {
  (void)state;
  return stack[slot];
}
static inline void stack_save(vm_state *state, gc_obj *stack, uint8_t slot,
                              gc_obj res) {
  (void)state;
  stack[slot] = res;
}
static inline gc_obj const_load(vm_state *state, bc *pc, uint16_t offset) {
  (void)state;
  return *(gc_obj *)(pc - pc->data);
}
static inline bc *vmgen_jmp_advance(bc *pc) { return pc + pc->data; }
static inline gc_obj emit_ov_math_add(vm_state *state, gc_obj v1, gc_obj v2) {
  (void)state;
  if (likely((is_fixnum(v1) & is_fixnum(v2)) == 1)) {
    // TODO overflow
    return tag_fixnum(to_fixnum(v1) + to_fixnum(v2));
  }
  if (likely((is_flonum(v1) & is_flonum(v2)) == 1)) {
    auto f1 = to_flonum(v1);
    auto f2 = to_flonum(v2);
    flonum_s *res = gc_alloc(sizeof(flonum_s));
    res->header.type = FLONUM_TAG;
    res->x = f1->x + f2->x;
    return tag_flonum(res);
  }
  // TODO other math types!
  abort();
}
static gc_obj scm_inexact(gc_obj v1) {
  if (is_fixnum(v1)) {
    flonum_s *res = gc_alloc(sizeof(flonum_s));
    res->header.type = FLONUM_TAG;
    res->x = (double)to_fixnum(v1);
    return tag_flonum(res);
  }
  if (is_flonum(v1)) {
    return v1;
  }
  abort();
}
static NOINLINE gc_obj emit_ov_math_sub_slow(vm_state *state, gc_obj v1,
                                             gc_obj v2) {
  if (is_flonum(v1) || is_flonum(v2)) {
    double r = to_flonum(scm_inexact(v1))->x - to_flonum(scm_inexact(v2))->x;
    flonum_s *res = gc_alloc(sizeof(flonum_s));
    res->header.type = FLONUM_TAG;
    res->x = r;
    return tag_flonum(res);
  }
  if (is_fixnum(v1) && is_fixnum(v2)) {
    gc_obj res;
    if (!__builtin_sub_overflow(v1.value, v2.value, &res.value)) {
      return res;
    }
    return emit_ov_math_sub_slow(state, scm_inexact(v1), scm_inexact(v2));
  }
  abort();
}
static inline gc_obj emit_ov_math_sub(vm_state *state, gc_obj v1, gc_obj v2) {
  (void)state;
  if (likely((is_fixnum(v1) & is_fixnum(v2)) == 1)) {
    // TODO overflow
    return tag_fixnum(to_fixnum(v1) - to_fixnum(v2));
  }
  if (likely((is_flonum(v1) & is_flonum(v2)) == 1)) {
    auto f1 = to_flonum(v1);
    auto f2 = to_flonum(v2);
    flonum_s *res = gc_alloc(sizeof(flonum_s));
    res->header.type = FLONUM_TAG;
    res->x = f1->x - f2->x;
    return tag_flonum(res);
  }
  MUSTTAIL return emit_ov_math_sub_slow(state, v1, v2);
}

static NOINLINE gc_obj emit_math_cmp_lt_slowpath(vm_state *state, bc *pc,
                                                 gc_obj *stack, gc_obj v1,
                                                 gc_obj v2) {
  bool res;
  /* if (is_compnum(a) || is_compnum(b)) { */
  /*   res = COMPCMP(a, b); */
  if (is_flonum(v1) || is_flonum(v2)) {
    res = to_flonum(scm_inexact(v1))->x < to_flonum(scm_inexact(v2))->x;
    /* } else if (is_ratnum(a) || is_ratnum(b)) { */
    /*   ratnum_s ba = get_ratnum(a); */
    /*   ratnum_s bb = get_ratnum(b); */
    /*   res = OP(ratnum_cmp(ba, bb), 0); */
    /* } else if (is_bignum(a) || is_bignum(b)) { */
    /*   mpz_t ba; */
    /*   mpz_t bb; */
    /*   get_bignum(a, &ba); */
    /*   get_bignum(b, &bb); */
    /*   res = OP(mpz_cmp(ba, bb), 0); */
  } else if (is_fixnum(v1) && is_fixnum(v2)) {
    res = to_fixnum(v1) < to_fixnum(v2);
  } else {
    // scm_runtime_error0("Invalid type in " #OPNAME);
    abort();
  }
  if (res) {
    return TRUE_REP;
  }
  return FALSE_REP;
}
static inline gc_obj emit_math_cmp_lt(vm_state *state, bc *pc, gc_obj *stack,
                                      gc_obj v1, gc_obj v2) {
  (void)state;
  (void)pc;
  (void)stack;
  if (likely((is_fixnum(v1) & is_fixnum(v2)) == 1)) {
    return to_fixnum(v1) < to_fixnum(v2) ? TRUE_REP : FALSE_REP;
  }
  if (likely((is_flonum(v1) & is_flonum(v2)) == 1)) {
    auto f1 = to_flonum(v1);
    auto f2 = to_flonum(v2);
    return f1->x < f2->x ? TRUE_REP : FALSE_REP;
  }
  // TODO other math types!
  MUSTTAIL return emit_math_cmp_lt_slowpath(state, pc, stack, v1, v2);
}
static inline gc_obj emit_math_cmp_eq(vm_state *state, bc *pc, gc_obj *stack,
                                      gc_obj v1, gc_obj v2) {
  (void)state;
  (void)pc;
  (void)stack;
  if (likely((is_fixnum(v1) & is_fixnum(v2)) == 1)) {
    return to_fixnum(v1) == to_fixnum(v2) ? TRUE_REP : FALSE_REP;
  }
  if (likely((is_flonum(v1) & is_flonum(v2)) == 1)) {
    auto f1 = to_flonum(v1);
    auto f2 = to_flonum(v2);
    return f1 == f2 ? TRUE_REP : FALSE_REP;
  }
  // TODO other math types!
  abort();
  (void)state;
}
static inline gc_obj emit_if_branch(vm_state *state, bc *pc, gc_obj *stack,
                                    gc_obj obj) {
  return obj;
}
static inline frame_state return_frame(vm_state *state, bc *pc, gc_obj *stack,
                                       void *op_table) {
  (void)state;
  auto ret = stack[pc->reg];
  auto new_pc = to_return_address(stack[-1]);
  auto old_pc = new_pc - 1;
  auto new_stack = stack - old_pc->reg - 1;
  new_stack[old_pc->reg] = ret;
  return (frame_state){.pc = new_pc, .stack = new_stack, .ops = op_table};
}
static inline bc *next_op(bc *pc) { return pc + 1; }
gc_obj halt(vm_state *state, gc_obj *stack) {
  profiler_stop();
  jit_dump_close();
  if (verbose) {
    printf("There were %li traces\n", arrlen(state->record.traces));
  }
  auto res = stack[0];
  free_traces(state);
  gc_remove_root((uint64_t *)state->stack_bottom);
  emit_cleanup(&state->emit);
  gc_free();
  free(state->stack_bottom);
  free(state);
  return res;
}
static inline void fail_if_not_closure(gc_obj clo) {
  if (!is_closure(clo)) {
    printf("Attempting to call a non-closure:");
    print_obj(clo, stdout);
    printf("\n");
    abort();
  }
}
static inline gc_obj sym_load(vm_state *state, gc_obj sym) {
  (void)state;
  auto s = to_symbol(sym);
  auto res = s->val;
  if (res.value == DEAD.value) {
    auto name = get_sym_name(s);
    printf("Symbol not defined: %.*s\n", (int)to_fixnum(name->len), name->str);
    abort();
  }
  return res;
}
static inline void sym_store(vm_state *state, gc_obj sym, gc_obj val) {
  (void)state;
  auto s = to_symbol(sym);
  if (s->opt > 0) {
    // TODO clear all traces
    printf("Muist abort optimistic globals\n");
    abort();
  }
  if (s->val.value != DEAD.value) {
    // If we've set this more than once, mark it as non-inlinable.
    s->opt = -1;
  }
  s->val = val;
}
static inline void obj_write(vm_state *state, gc_obj val, void **op_table) {
  print_obj(val, stdout);
}
void expand_stack(vm_state *state, gc_obj **stack) {
  // TODO: this should really be a stack *cache*
  size_t oldsz = (size_t)(state->stack_top - state->stack_bottom);
  size_t newsz = oldsz + (oldsz / 3);
  if (newsz <= oldsz) {
    newsz = oldsz + 1;
  }
  gc_obj *old_bottom = state->stack_bottom;
  auto offset = *stack - state->stack_bottom;
  if (verbose) {
    printf("MUST EXPAND STACK now %li\n", newsz);
  }
  gc_remove_root((const uint64_t *)old_bottom);
  gc_obj *newstack = realloc(state->stack_bottom, sizeof(gc_obj) * newsz);
  if (!newstack) {
    fprintf(stderr, "Failed to realloc stack\n");
    abort();
  }
  // Since we're a conservative GC, no need to zero.
  /* memset(&newstack[oldsz], 0, grow * sizeof(gc_obj)); */
  state->stack_bottom = newstack;
  state->stack_top = newstack + newsz;
  state->stack_limit = state->stack_top - STACK_GUARD_SLOTS;
  // Potential improvement: the GC could callback to get the current stack size.
  // (or rather, stack + 256 redzone).
  // If the stack grew large but then stayed small, GC time would be improved.
  gc_add_root((const uint64_t *)state->stack_bottom, newsz);
  *stack = &newstack[offset];
}

static inline void check_expand_stack(vm_state *state, gc_obj **stack) {
  if (*stack >= state->stack_limit) {
    expand_stack(state, stack);
  }
}
static inline void check_arity(int expected, uint8_t args) {
  if (args != expected) {
    printf("Bad argcnt expected %i got %i\n", expected, args);
    abort();
  }
}
static inline bc *branch_if_op(vm_state *state, bc *pc, gc_obj *stack,
                               gc_obj b) {
  (void)state;
  (void)stack;
  pc++; // Next opcode must be JMP.
  if (b.value == FALSE_REP.value) {
    // follow jmp.
    return pc + pc->data;
  }
  // skip jmp.
  return pc + 1;
}
static inline gc_obj closure_get(vm_state *state, gc_obj *stack, gc_obj clo,
                                 uint8_t slot, uint8_t clo_idx) {
  (void)state;
  (void)stack;
  (void)clo_idx;
  return to_closure(clo)->v[slot];
}
static inline void store_obj(vm_state *state, gc_obj *stack, bc *pc) {
  (void)state;
  auto dest = stack_load(state, stack, pc->reg, true);
  auto val = stack_load(state, stack, pc->v1, false);
  auto off = stack_load(state, stack, pc->v2, true);
  assert(is_heap_object(dest));
  assert(is_fixnum(off));

  auto base = (gc_obj *)((uint8_t *)to_raw_ptr(dest) + sizeof(gc_header));
  base[to_fixnum(off)] = val;
}
static inline gc_obj load_obj(vm_state *state, gc_obj *stack, bc *pc) {
  (void)state;
  auto src = stack_load(state, stack, pc->v1, true);
  auto off = stack_load(state, stack, pc->v2, true);
  assert(is_heap_object(src));
  assert(is_fixnum(off));

  auto base = (gc_obj *)((uint8_t *)to_raw_ptr(src) + sizeof(gc_header));
  return base[to_fixnum(off)];
}
static inline gc_obj alloc_obj(vm_state *state, gc_obj *stack, bc *pc) {
  (void)state;
  auto sz_obj = stack_load(state, stack, pc->v1, true);
  auto type_obj = stack_load(state, stack, pc->v2, true);
  assert(is_fixnum(sz_obj));
  assert(is_fixnum(type_obj));
  uint64_t sz = (uint64_t)to_fixnum(sz_obj);
  uint64_t type = (uint64_t)to_fixnum(type_obj);
  assert((sz & 0x7) == 0);

  auto obj = (gc_header *)gc_alloc(sz);
  obj->type = type;
  return type < 8 ? tag_header(obj, (uint8_t)type) : tag_header(obj, PTR_TAG);
}
static inline gc_obj guard_obj(vm_state *state, gc_obj *stack, bc *pc) {
  (void)state;
  auto val = stack_load(state, stack, pc->v1, false);
  auto want_tag_obj = stack_load(state, stack, pc->v2, true);

  return guard_obj_matches(val, want_tag_obj) ? TRUE_REP : FALSE_REP;
}
static inline gc_obj closure_alloc(vm_state *state, gc_obj *stack, bc *pc) {
  (void)state;
  uint64_t sz = (uint64_t)pc->data + 1;
  uint8_t start = pc->reg;
  closure_s *clo = gc_alloc(sizeof(closure_s) + (sizeof(gc_obj) * sz));
  clo->header.type = CLOSURE_TAG;
  clo->len = tag_fixnum((int64_t)sz);
  for (uint64_t i = 0; i < sz; i++) {
    clo->v[i] = stack[start + i];
  }
  return tag_closure(clo);
}
static inline void closure_set(vm_state *state, gc_obj clo, uint8_t slot,
                               gc_obj val, void **op_table) {
  (void)state;
  (void)op_table;
  to_closure(clo)->v[slot] = val;
}
static inline gc_obj return_address(vm_state *state, bc *ra) {
  (void)state;
  return tag_return_address(ra);
}
static inline gc_obj *adjust_stack_depth(vm_state *state, gc_obj *stack,
                                         int depth) {
  (void)state;
  // TODO check stack depth?
  return stack + depth;
}
static inline void stack_memmov(vm_state *state, gc_obj *stack, uint16_t from,
                                uint16_t cnt) {
  memmove(&stack[0], &stack[from], cnt * sizeof(gc_obj));
}
static inline bc *set_new_pc(vm_state *state, bc *pc, gc_obj *stack,
                             gc_obj func) {
  (void)state;
  auto bfunc = to_func(func);
  return (bc *)(&bfunc->data[bfunc->const_cnt * sizeof(gc_obj)]);
}
static inline gc_obj constify_data(vm_state *state, uint16_t data) {
  (void)state;
  return (gc_obj){.value = data};
}

static inline void *jit_func(bc *instr, bc **pc, gc_obj **stack,
                             vm_state *state, void *op_table, uint8_t *argcnt) {
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

  // Check if a return trace - return trace aborts to JFUNC, but we need to
  // actually run RET
  if ((*pc)->op == OP_JFUNC) {
    auto trace = traces[(*pc)->data];
    if (trace->num == res.snap->trace->num && trace->start_pc.op == OP_RET) {
      (*pc) = &trace->start_pc;
      *instr = **pc;
    }
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
      if (res.snap->ir == 0) {
        // It's a special, new-root trace!
        // This happens when ARG typechecks fail.
        if (verbose) {
          printf("Try NEW root trace %i %i\n", res.snap->trace->num,
                 res.snap->ir);
        }
        bc start = res.snap->trace->start_pc;
        *instr = start;
        record_start(state, *pc, start, *stack, res.snap);
        if (start.op != OP_RET) {
          // Skip over FUNC/JFUNC so we actually record body instructions.
          *pc = next_op(*pc);
          *instr = **pc;
        }
      } else {
        if (verbose) {
          printf("Try side trace %i %i\n", res.snap->trace->num, res.snap->ir);
        }
        record_start_side(state, *pc, **pc, *stack, res.snap);
      }
      return state->record_impls;
    }
  }
  if (res.snap->ir == 0 && res.snap->trace->parent == nullptr) {
    // We aborted because of typechecking arguments,
    // we're pointing at a OP_JFUNC, when we really want to run the code
    // directly.
    *instr = res.snap->trace->start_pc;
    // arity was already checked, just patch it here.
    *argcnt = instr->reg;
  }

  // printf("RUN DONE jit %i\n", jfunc);
  return op_table;
}
#define dispatch_next(pc, stack)                                               \
  op_func impl = ((op_func *)op_table)[(pc)->op];                              \
  MUSTTAIL return impl(*(pc), (pc), (stack), state, op_table, argcnt);

// NOLINTNEXTLINE(bugprone-suspicious-include)
#include "vmgen.c" // NOLINT(build/include)

#define X(name, type)                                                          \
  PRESERVE_NONE gc_obj record_##name(bc instr, bc *pc, gc_obj *stack,          \
                                     vm_state *state, void *op_table,          \
                                     uint8_t argcnt);
OPS;
#undef X

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
#define X(name, type) state->record_impls[OP_##name] = record_##name;
      OPS
#undef X
}

gc_obj vm(bc *pc) {
  size_t default_size = 1024;
  vm_state *state = calloc(1, sizeof(vm_state));
  vm_state_init(state);

  gc_obj *stack = calloc(default_size, sizeof(gc_obj));
  if (!stack) {
    fprintf(stderr, "Failed to allocate VM stack\n");
    exit(EXIT_FAILURE);
  }
  state->stack_bottom = stack;
  state->stack_top = stack + default_size;
  state->stack_limit = state->stack_top - STACK_GUARD_SLOTS;
  gc_add_root((const uint64_t *)state->stack_bottom, default_size);
  if (profile) {
    profiler_start();
  }

  return state->impls[pc->op](*pc, pc, stack, state, state->impls, 0);
}
