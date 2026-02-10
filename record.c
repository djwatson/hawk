#include <assert.h>
#include <stdlib.h>

#include "array.h"
#include "bc.h"
#include "emit.h"
#include "fold.h"
#include "gc.h"
#include "hashtable.h"
#include "hawk.h"
#include "ir.h"
#include "opt_dce.h"
#include "record.h"
#include "string.h"
#include "types.h"
#include "vm.h"
#include "vm_guard.h"

#define VMGEN_TRACE_OP_NOABORT(pc, code, state, argcnt)                        \
  do {                                                                         \
    if (verbose) {                                                             \
      print_record_debug((pc), #code, (state));                                \
    }                                                                          \
  } while (0)
#define VMGEN_TRACE_OP(pc, code, state, argcnt)                                \
  do {                                                                         \
    VMGEN_TRACE_OP_NOABORT(pc, code, state, argcnt);                           \
    trace_state *ts = record_trace_state((state));                             \
    trace *cur_trace = record_current_trace((state));                          \
    if (ts->depth >= 20 || arrlen(cur_trace->ins) >= 500) {                    \
      if (verbose) {                                                           \
        printf("Record abort: too long or too deep\n");                        \
      }                                                                        \
      record_abort((state));                                                   \
      op_table = (state)->impls;                                               \
      op_func impl = ((op_func *)op_table)[(pc)->op];                          \
      MUSTTAIL return impl(*(pc), (pc), stack, (state), (state)->impls,        \
                           (argcnt));                                          \
    }                                                                          \
  } while (0)
static bool is_downrec_trace(trace_state *ts) { return ts->start_is_ret; }

enum {
  BLACKLIST_MAX = 64,
};

static const char *func_name_from_pc(bc *pc) {
  assert(pc);
  bcfunc *func = gc_base_ptr(pc);
  return to_string(func->name)->str;
}

static uint32_t find_penalty_pc(record_state *record, const bc *pc) {
  auto idx = hm_geti(record->blacklist, (bc *)pc);
  if (idx >= 0) {
    return record->blacklist[idx].value;
  }
  return 0;
}

static void penalty_pc(record_state *record, bc *pc) {
  if (!pc) {
    return;
  }

  auto idx = hm_geti(record->blacklist, pc);
  if (idx >= 0) {
    auto cnt = ++record->blacklist[idx].value;
    if (cnt >= BLACKLIST_MAX) {
      if (verbose) {
        const char *fname = func_name_from_pc(pc);
        printf("Blacklist pc %p %s\n", pc, fname);
      }
      if (pc->op == OP_FUNC) {
        pc->op = OP_IFUNC;
      } else if (verbose) {
        const char *fname = func_name_from_pc(pc);
        printf("Could not blacklist %s %s\n", bc_names[pc->op], fname);
      }
      hm_del(record->blacklist, pc);
    }
    return;
  }

  hm_put(record->blacklist, pc, 1);
}

static void clear_trace_state(trace_state *ts) {
  arrfree(ts->stack);
  arrfree(ts->downrec);
  ts->poly_entry = nullptr;
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
static void print_record_debug(bc *pc, char *code, vm_state *state) {
  trace_state *ts = record_trace_state(state);
  for (int i = 0; i < ts->depth; i++) {
    printf(" . ");
  }
  printf("record op: %p %s reg:%i, v1:%i v2:%i", pc, code, pc->reg, pc->v1,
         pc->v2);
  const char *fname = func_name_from_pc(pc);
  printf(" %s", fname);
  printf("\n");
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
  arrput(state->record.traces, trace);
}

static void snapshot_live_slots(trace_state *ts, snap *snap) {
  arr_for_each_idx(ts->stack, i) {
    sentry entry = ts->stack[i];
    if (entry.changed && entry.live) {
      snap_entry slot = {.slot = (uint16_t)i, .val = entry.loc};
      arrput(snap->slots, slot);
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
  record->blacklist = nullptr;
}

static slot add_const(vm_state *state, gc_obj value) {
  trace *trace_obj = record_current_trace(state);
  auto idx = arrlen(trace_obj->consts);
  arrput(trace_obj->consts, value);
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
  if (arrlen(cur_trace->snaps) > 2 && arrlast(cur_trace->snaps)->ir == sn.ir) {
    auto old = arrlast(cur_trace->snaps);
    arrpop(cur_trace->snaps);
    free_snap(old);
  }
  arrput(cur_trace->snaps, sn);
}

static void ensure_stack_len(trace_state *ts, uint32_t need) {
  auto len = arrlen(ts->stack);
  while (len < need) {
    sentry entry = {.live = false, .changed = false};
    arrput(ts->stack, entry);
    len++;
  }
}

static sentry *get_sentry(vm_state *state, uint64_t idx) {
  trace_state *ts = record_trace_state(state);
  ensure_stack_len(ts, ts->stack_off + idx + 1);
  return &ts->stack[idx + ts->stack_off];
}

static sentry *get_sentry_abs(vm_state *state, uint64_t abs_idx) {
  trace_state *ts = record_trace_state(state);
  ensure_stack_len(ts, abs_idx + 1);
  return &ts->stack[abs_idx];
}

static void set_stack_abs(vm_state *state, uint16_t abs_slot, slot val) {
  auto entry = get_sentry_abs(state, abs_slot);
  *entry = (sentry){
      .live = true,
      .changed = true,
      .loc = val,
  };
}

static inline void set_stack_len(trace_state *ts, uint32_t len) {
  ensure_stack_len(ts, ts->stack_off + len);
  arrlen_set(ts->stack, ts->stack_off + len);
}

static slot add_inst(vm_state *state, ir_ins ins) {
  trace *trace_obj = record_current_trace(state);
  auto fold_res = fold_instr(trace_obj, &ins);
  if (fold_res.action == FOLD_DROP) {
    return (slot){.constant = false, .loc = 0x7fff};
  }
  if (fold_res.action == FOLD_CONST) {
    return add_const(state, fold_res.constant);
  }

  auto idx = arrlen(trace_obj->ins);
  arrput(trace_obj->ins, ins);
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
  trace_state *ts = record_trace_state(state);
  ir_ins ins = IR(.op = IR_SLOAD, .data = pos + ts->stack_off,
                  .type = get_type_tag(stack[pos]), .guard = typecheck);

  set_stack(state, pos, add_inst(state, ins));
  entry->changed = false;
  return entry->loc;
}
static void stack_save(vm_state *state, gc_obj *stack, uint8_t pos, slot res) {
  set_stack(state, pos, res);
}
static inline void set_stack_top(vm_state *state, uint8_t top) {
  trace_state *ts = record_trace_state(state);
  set_stack_len(ts, (uint32_t)top);
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
static slot emit_ov_math_mul(vm_state *state, slot v1, slot v2) {
  (void)state;
  (void)v1;
  (void)v2;
  // TODO: recording/JIT support for MUL.
  abort();
}
static slot emit_ov_math_mod(vm_state *state, slot v1, slot v2) {
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
      IR(.op = IR_MOD, .op1 = v1, .op2 = v2, .type = get_slot_type(t, v1));
  return add_inst(state, ins);
}
static inline double numeric_to_double(gc_obj v) {
  if (is_flonum(v)) {
    return to_flonum(v)->x;
  }
  if (is_fixnum(v)) {
    return (double)to_fixnum(v);
  }
  abort();
}

#define DEFINE_BRANCH_CMP(name, taken_op, not_taken_op, cmp_op)                \
  static branch_result emit_math_cmp_##name(vm_state *state, bc *pc,           \
                                            gc_obj *stack, slot v1, slot v2) { \
    auto lhs = stack[pc->v1];                                                  \
    auto rhs = stack[pc->v2];                                                  \
    bool res;                                                                  \
    if (is_flonum(lhs) || is_flonum(rhs)) {                                    \
      res = numeric_to_double(lhs) cmp_op numeric_to_double(rhs);              \
    } else if (is_fixnum(lhs) && is_fixnum(rhs)) {                             \
      res = to_fixnum(lhs) cmp_op to_fixnum(rhs);                              \
    } else {                                                                   \
      abort();                                                                 \
    }                                                                          \
    auto t = record_current_trace(state);                                      \
    auto t1 = get_slot_type(t, v1);                                            \
    auto t2 = get_slot_type(t, v2);                                            \
    if (t1 == FLONUM_TAG || t2 == FLONUM_TAG) {                                \
      v1 = convert_to_flonum(state, v1);                                       \
      v2 = convert_to_flonum(state, v2);                                       \
    } else if (t1 == FIXNUM_TAG && t2 == FIXNUM_TAG) {                         \
      /* OK. */                                                                \
    } else {                                                                   \
      abort();                                                                 \
    }                                                                          \
                                                                               \
    branch_result br = {                                                       \
        .taken = res,                                                          \
        .guard = IR(.op = (res) ? (taken_op) : (not_taken_op), .op1 = v1,      \
                    .op2 = v2,                                                 \
                    .type = get_slot_type(record_current_trace(state), v1)),   \
    };                                                                         \
    return br;                                                                 \
  }

DEFINE_BRANCH_CMP(lt, IR_LT, IR_GTE, <)
DEFINE_BRANCH_CMP(gt, IR_GT, IR_LTE, >)
DEFINE_BRANCH_CMP(lte, IR_LTE, IR_GT, <=)
DEFINE_BRANCH_CMP(gte, IR_GTE, IR_LT, >=)
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
static void record_abort(vm_state *state) {
  trace_state *ts = record_trace_state(state);
  penalty_pc(&state->record, ts->start_ins);
  trace *cur_trace = record_current_trace(state);
  if (ts->poly_entry) {
    ts->poly_entry = nullptr;
  }
  if (cur_trace) {
    free_trace(cur_trace);
  }
  record_set_current_trace(state, nullptr);
  clear_trace_state(ts);
}
static void record_finish(bc *pc, vm_state *state) {
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  vm_add_snap(state, pc);
  dce(cur_trace);
  cur_trace->fn =
      emit(cur_trace, &state->emit, &state->record, cur_trace->link_entry_snap);
  state->max_trace--;
  if (ts->type == TRACE_TYPE_ROOT) {
    *ts->start_ins = (bc){
        .op = OP_JFUNC,
        .data = record_trace_count(state),
    };
  }
  if (ts->poly_entry) {
    // Only install polymorphic chaining after successful recording.
    ts->poly_entry->trace->next = cur_trace;
  }
  record_append_trace(state, cur_trace);
  clear_trace_state(ts);
  record_set_current_trace(state, nullptr);
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
static frame_state return_frame(vm_state *state, bc instr, bc *pc,
                                gc_obj *stack, void *op_table) {
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
  set_stack_len(ts, instr.reg + 1);

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
      record_start(state, pc, *pc, stack);
      // UGH there must be a better way?
      VMGEN_TRACE_OP_NOABORT(pc, RET, state, 0);
      return return_frame(state, *pc, pc, stack, op_table);
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
    auto res = stack_load(state, stack, instr.reg, false);
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
    arrput(ts->downrec, pc);
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

    auto ret = stack_load(state, stack, instr.reg, false);
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
  ir_ins ins = IR(.op = IR_GGET, .op1 = sym, .type = get_type_tag(s->val));

  return add_inst(state, ins);
}
static void sym_store(vm_state *state, slot sym, slot val) {
  ir_ins ins = IR(.op = IR_GSET, .op1 = sym, .op2 = val);
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
  vm_add_snap(state, pc + 1);
}
static slot load_obj(vm_state *state, gc_obj *stack, bc *pc) {
  auto obj = stack_load(state, stack, pc->v1, true);
  auto offset = stack_load(state, stack, pc->v2, true);
  // Peek at leaded type
  auto src = stack[pc->v1];
  auto off = stack[pc->v2];
  auto base = (gc_obj *)((uint8_t *)to_raw_ptr(src) + sizeof(gc_header));
  auto type = get_type_tag(base[to_fixnum(off)]);

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
  (void)op_table;

  slot c_pos = add_const(state, tag_fixnum(pos + 1));
  auto ref = add_inst(state, IR(.op = IR_REF, .op1 = clo, .op2 = c_pos));
  add_inst(state,
           IR(.op = IR_STORE, .op1 = ref, .op2 = val, .type = CLOSURE_TAG));
}
static slot closure_alloc(vm_state *state, gc_obj *stack, bc *pc) {
  uint64_t capture_cnt = (uint64_t)pc->data + 1;
  uint8_t start = pc->reg;
  int64_t size_bytes =
      (int64_t)(sizeof(closure_s) + (capture_cnt * sizeof(gc_obj)));

  auto sz = add_const(state, tag_fixnum(size_bytes));
  auto type = add_const(state, tag_fixnum(CLOSURE_TAG));
  ir_ins ins = IR(.op = IR_ALLOC, .op1 = sz, .op2 = type, .type = CLOSURE_TAG);
  auto clo = add_inst(state, ins);

  // Initialize closure length.
  slot len_off = add_const(state, tag_fixnum(0));
  slot len_val = add_const(state, tag_fixnum((int64_t)capture_cnt));
  auto len_ref = add_inst(state, IR(.op = IR_REF, .op1 = clo, .op2 = len_off));
  add_inst(state, IR(.op = IR_STORE, .op1 = len_ref, .op2 = len_val,
                     .type = CLOSURE_TAG));

  // Capture values from the stack, matching the VM behavior.
  for (uint64_t i = 0; i < capture_cnt; i++) {
    auto val = stack_load(state, stack, (uint8_t)(start + i), false);
    closure_set(state, clo, (uint8_t)i, val, nullptr);
  }

  return clo;
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
  if (clo.constant) {
    auto trace = record_current_trace(state);
    auto c = to_closure(trace->consts[clo.loc]);
    auto res = c->v[pos];
    return add_const(state, res);
  }
  // IR_LOAD now applies header/tag adjustment in emit; keep this as slot index.
  slot c_pos = add_const(state, tag_fixnum(pos + 1));

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

static int pmov_arg_index(trace *t, uint16_t ins_loc);

static int slot_arg_index(trace *t, slot s) {
  if (s.constant) {
    return -1;
  }
  ir_ins *ins = &t->ins[s.loc];
  if (ins->op == IR_ARG) {
    return (int)ins->data;
  }
  if (ins->op == IR_PMOV) {
    return pmov_arg_index(t, s.loc);
  }
  return -1;
}

static int pmov_arg_index(trace *t, uint16_t ins_loc) {
  if (arrlen(t->snaps) == 0) {
    return -1;
  }
  snap *entry_snap = &t->snaps[0];
  arr_for_each_idx(entry_snap->slots, i) {
    auto entry = &entry_snap->slots[i];
    if (entry->val.constant || entry->val.loc != ins_loc) {
      continue;
    }
    int logical_slot = (int)entry->slot - (int)entry_snap->offset;
    if (logical_slot < 0 || logical_slot >= REG_ARG_CNT) {
      return -1;
    }
    return logical_slot;
  }
  return -1;
}

typedef struct {
  trace *trace;
  bool matched;
} trace_match;

static trace_match ensure_args_match_trace(vm_state *state, gc_obj *stack,
                                           trace *head, trace *cur_trace) {
  trace_match res = {.trace = head, .matched = false};

  if (verbose && head) {
    printf("Arg match head trace %i\n", head->num);
  }
  for (trace *candidate = head; candidate; candidate = candidate->next) {
    if (verbose) {
      printf("Arg match? trace %i\n", candidate->num);
    }
    bool needs_guard[REG_ARG_CNT] = {0};
    bool match = true;

    arr_for_each_idx(candidate->ins, i) {
      ir_ins *ins = &candidate->ins[i];
      if (ins->op == IR_ARG) {
        continue;
      }
      if (ins->op == IR_PMOV) {
        if (!ins->guard) {
          continue;
        }
        int arg_idx = pmov_arg_index(candidate, (uint16_t)i);
        if (arg_idx < 0 || arg_idx >= REG_ARG_CNT) {
          // Guarded PMOV without an entry-arg mapping is ambiguous.
          // Reject this candidate rather than guessing.
          match = false;
          break;
        }
        needs_guard[arg_idx] = true;
        if (verbose) {
          printf("  need_guard[arg%d] = 1 (pmov ins=%zu type=%u)\n", arg_idx, i,
                 ins->type);
        }
        if (get_type_tag(stack[arg_idx]) != ins->type) {
          if (verbose) {
            printf("  arg%d type mismatch want %u got %u\n", arg_idx, ins->type,
                   get_type_tag(stack[arg_idx]));
          }
          match = false;
          break;
        }
        continue;
      }
      if (ins->op != IR_TYPECHECK) {
        break;
      }
      if (!ins->guard) {
        continue;
      }
      int arg_idx = slot_arg_index(candidate, ins->op1);
      if (arg_idx < 0 || arg_idx >= REG_ARG_CNT) {
        continue;
      }
      needs_guard[arg_idx] = true;
      if (verbose) {
        printf("  need_guard[arg%d] = 1 (typecheck ins=%zu type=%u)\n", arg_idx,
               i, ins->type);
      }
      if (get_type_tag(stack[arg_idx]) != ins->type) {
        if (verbose) {
          printf("  arg%d type mismatch want %u got %u\n", arg_idx, ins->type,
                 get_type_tag(stack[arg_idx]));
        }
        match = false;
        break;
      }
    }

    if (!match) {
      if (verbose) {
        printf("  needs_guard:");
        for (int arg_idx = 0; arg_idx < REG_ARG_CNT; arg_idx++) {
          if (needs_guard[arg_idx]) {
            printf(" %d", arg_idx);
          }
        }
        printf("\n");
      }
      continue;
    }

    if (cur_trace) {
      // A trace is only safe to match if every required entry-arg guard can be
      // re-applied from the side trace's outgoing state. If an arg isn't in the
      // outgoing snapshot (not live/changed), linking here would skip a
      // required type guard on re-entry.
      for (int arg_idx = 0; arg_idx < REG_ARG_CNT; arg_idx++) {
        if (!needs_guard[arg_idx]) {
          continue;
        }
        sentry *entry = get_sentry(state, arg_idx);
        if (!entry->live || !entry->changed) {
          if (verbose) {
            printf("  reject trace %i: missing outgoing snap slot for arg%d "
                   "(live=%d changed=%d)\n",
                   candidate->num, arg_idx, entry->live, entry->changed);
          }
          match = false;
          break;
        }
      }
      if (!match) {
        continue;
      }
    }

    res.trace = candidate;
    res.matched = true;
    if (verbose) {
      printf("  matched trace %i\n", candidate->num);
      printf("  needs_guard:");
      bool any_needs_guard = false;
      for (int arg_idx = 0; arg_idx < REG_ARG_CNT; arg_idx++) {
        if (needs_guard[arg_idx]) {
          printf(" %d", arg_idx);
          any_needs_guard = true;
        }
      }
      if (!any_needs_guard) {
        printf(" (none)");
      }
      printf("\n");
    }

    if (cur_trace) {
      for (int arg_idx = 0; arg_idx < REG_ARG_CNT; arg_idx++) {
        if (!needs_guard[arg_idx]) {
          continue;
        }
        if (verbose) {
          printf("  propagate guard for arg%d\n", arg_idx);
        }
        sentry *entry = get_sentry(state, arg_idx);
        if (!entry->live || !entry->changed || entry->loc.constant) {
          if (verbose) {
            printf("    skip arg%d guard propagation (live=%d changed=%d "
                   "constant=%d)\n",
                   arg_idx, entry->live, entry->changed, entry->loc.constant);
          }
          continue;
        }
        cur_trace->ins[entry->loc.loc].guard = true;
        if (verbose) {
          printf("    set guard on cur_trace ins=%u for arg%d\n",
                 entry->loc.loc, arg_idx);
        }
      }
    }
    break;
  }

  return res;
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
  trace_match match = ensure_args_match_trace(state, *stack, target, cur_trace);

  if (cur_trace->parent) {
    cur_trace->link = match.trace;
    cur_trace->link_entry_snap = match.matched ? 1 : 0;
    if (verbose) {
      printf("Record stop: side trace linked to root trace\n");
    }
    record_finish(*pc, state);
    return state->impls;
  }
  // TODO
  record_abort(state);
  if (verbose) {
    printf("Record abort: Root trace to JFUNC\n");
  }
  return state->impls;
}
static void *check_record_start(bc *pc, gc_obj *stack, vm_state *state,
                                void *op_table) {
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  if (arrlen(cur_trace->ins) <= ts->start_record_size) {
    return op_table;
  }
  int64_t cnt = 0;
  if (pc->op == OP_FUNC) {
    auto p_pc = to_return_address(stack[-1]);
    auto ret_pc = p_pc;
    auto pstack = stack;
    for (auto d = ts->depth - 1; d > 0; d--) {
      pstack = pstack - (p_pc - 1)->reg - 1;
      p_pc = to_return_address(pstack[-1]);
      if (p_pc == ret_pc) {
        cnt++;
      }
    }
  }
  // Several cases.
  // parent trace:
  //  depth == 0: tailcalled loop.
  //  depth != 0: up-recursion.
  // side trace:
  //  check for up-recursion and abort, restart trying to capture an
  //  up-recursive trace.
  if (pc == ts->start_ins && !is_downrec_trace(ts)) {
    trace_match match =
        ensure_args_match_trace(state, stack, cur_trace, cur_trace);
    cur_trace->link = match.trace;
    cur_trace->link_entry_snap = match.matched ? 1 : 0;
    if (verbose) {
      if (ts->depth != 0) {
        printf("Record stop: up-recursion\n");
      } else {
        printf("Record stop: root loop\n");
      }
    }
    record_finish(pc, state);
    return state->impls;
  }
  if (pc != ts->start_ins && cnt > 0) {
    if (verbose) {
      printf("Record abort: uprec detected, restart\n");
    }
    record_abort(state);
    return state->impls;
  }
  return op_table;
}

// Tailcall to the non-recording version, which will then tailcall the
// next *recording* opcode
#define dispatch_next(pc, stack)                                               \
  op_func impl = state->impls[instr.op];                                       \
  MUSTTAIL return impl(instr, (pc), (stack), state, op_table, argcnt);

// NOLINTNEXTLINE(bugprone-suspicious-include)
#include "vmgen.c" // NOLINT(build/include)

void record_start(vm_state *state, bc *pc, bc instr, gc_obj *stack) {

  if (verbose) {
    const char *fname = func_name_from_pc(pc);
    printf("Record start %p %i %s %s\n", pc, record_trace_count(state), fname,
           instr.op == OP_RET ? "DOWNREC" : "");
  }
  record_set_current_trace(state, calloc(1, sizeof(trace)));
  record_current_trace(state)->start_pc = instr;
  record_current_trace(state)->num = record_trace_count(state);
  trace_state *ts = record_trace_state(state);
  memset(ts, 0, sizeof(trace_state));
  ts->start_ins = pc;
  ts->start_is_ret = (instr.op == OP_RET);
  ts->type = TRACE_TYPE_ROOT;
  ts->poly_entry = nullptr;

  // OK! Let's put function arguments in registers.
  // Note these *must* be marked as 'changed', since ARGS aren't saved between
  // trace loops at all.
  assert(instr.op == OP_FUNC || instr.op == OP_RET);
  switch (instr.op) {
  case OP_FUNC:
    for (int i = 0; i < MIN(instr.reg, REG_ARG_CNT); i++) {
      set_stack(
          state, i,
          add_inst(state, IR(.op = IR_ARG, .data = i, .type = UNDEFINED_TAG)));
    }
    break;
  case OP_RET:
    set_stack(state, instr.reg,
              add_inst(state, IR(.op = IR_ARG, .data = instr.reg,
                                 .type = UNDEFINED_TAG)));

    break;
  default:
    abort();
  }
  vm_add_snap(state, pc);
  // Typecheck entry arguments up-front so later uses can target the checked
  // value.
  switch (instr.op) {
  case OP_FUNC:
    for (int i = 0; i < MIN(instr.reg, REG_ARG_CNT); i++) {
      auto s = get_sentry(state, i);
      auto checked = add_inst(state, IR(.op = IR_TYPECHECK, .op1 = s->loc,
                                        .type = get_type_tag(stack[i])));
      set_stack(state, i, checked);
    }
    break;
  case OP_RET: {
    auto s = get_sentry(state, instr.reg);
    auto checked = add_inst(state, IR(.op = IR_TYPECHECK, .op1 = s->loc,
                                      .type = get_type_tag(stack[instr.reg])));
    set_stack(state, instr.reg, checked);
    break;
  }
  default:
    abort();
  }
  vm_add_snap(state, pc);
  ts->start_record_size = arrlen(record_current_trace(state)->ins);
}

void record_start_side(vm_state *state, bc *pc, bc instr, gc_obj *stack,
                       snap *side_snap, const snap *poly_entry) {
  if (verbose) {
    printf("Record start side %i\n", record_trace_count(state));
  }
  assert(instr.op != OP_JFUNC);
  record_set_current_trace(state, calloc(1, sizeof(trace)));
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  cur_trace->parent = side_snap->trace;
  cur_trace->parent_snap = side_snap;
  cur_trace->start_pc = instr;
  cur_trace->num = record_trace_count(state);
  memset(ts, 0, sizeof(trace_state));
  ts->start_ins = pc;
  ts->start_is_ret = (instr.op == OP_RET);
  ts->depth = side_snap->depth;
  ts->stack_off = 0;
  ts->type = TRACE_TYPE_SIDE;
  ts->poly_entry = poly_entry;

  // Replay snapshot loads, so we keep things in register.
  arr_for_each_idx(side_snap->slots, j) {
    auto entry = &side_snap->slots[j];
    if (entry->val.constant) {
      set_stack(state, entry->slot,
                add_const(state, side_snap->trace->consts[entry->val.loc]));
    } else {
      auto old_ins = &side_snap->trace->ins[entry->val.loc];
      if (old_ins->spill != SPILL_NONE) {
        abort();
      } else {
        set_stack(state, entry->slot,
                  add_inst(state,
                           IR(.op = IR_PMOV, .prev_reg = old_ins->reg,
                              .prev_guard = old_ins->guard,
                              .guard = old_ins->guard, .type = old_ins->type)));
      }
    }
  }
  // We set this last, since snapshots have absolute indexs, and set_stack is
  // relative to stack_off.
  ts->stack_off = side_snap->offset;
  vm_add_snap(state, pc);

  // Insert initial typechecks for replayed values.
  arr_for_each_idx(side_snap->slots, j) {
    auto entry = &side_snap->slots[j];
    if (entry->val.constant) {
      continue;
    }
    auto s = get_sentry_abs(state, entry->slot);
    auto old_ins = &side_snap->trace->ins[entry->val.loc];
    int64_t rel_slot = (int64_t)entry->slot - (int64_t)ts->stack_off;
    if (old_ins->guard || old_ins->type == FLONUM_TAG) {
      // Already typechecked.
      continue;
    }
    auto checked = add_inst(state, IR(.op = IR_TYPECHECK, .op1 = s->loc,
                                      .type = get_type_tag(stack[rel_slot])));
    set_stack_abs(state, entry->slot, checked);
  }
  vm_add_snap(state, pc);
  ts->start_record_size = arrlen(record_current_trace(state)->ins);
}

void free_traces(struct vm_state *state) {
  auto rs = &state->record;
  arr_for_each(rs->traces, trace) { free_trace(trace); }
  arrfree(rs->trace_state.stack);
  arrfree(rs->traces);
  hm_free(rs->blacklist);
  rs->cur_trace = nullptr;
}
