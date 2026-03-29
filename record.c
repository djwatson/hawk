#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "array.h"
#include "bc.h"
#include "box_closure_flonums.h"
#include "emit.h"
#include "fold.h"
#include "foreign.h"
#include "gc.h"
#include "hashtable.h"
#include "hawk.h"
#include "ir.h"
#include "opt_dce.h"
#include "record.h"
#include "runtime.h"
#include "string.h"
#include "types.h"
#include "vm.h"

static bool is_downrec_trace(trace_state *ts) { return ts->start_is_ret; }

enum {
  BLACKLIST_MAX = 32,
  func_flag_rest = 1,
};

static const char *func_name_from_pc(bc *pc) {
  assert(pc);
  bcfunc *func = gc_base_ptr(pc);
  return to_string(func->name)->str;
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
      record->blacklist[idx].value = BLACKLIST_MAX;
      if (pc->op == OP_FUNC) {
        pc->op = OP_IFUNC;
      }
    }
    return;
  }

  hm_put(record->blacklist, pc, 1);
}

static void clear_trace_state(trace_state *ts) {
  arrfree(ts->stack);
  arrfree(ts->downrec);
  *ts = (trace_state){0};
}
static void free_snap(snap *snap) { arrfree(snap->slots); }
static void free_trace(trace *trace) {
  arr_for_each(trace->snaps, snap) { free_snap(&snap); }
  arrfree(trace->ins);
  arrfree(trace->consts);
  arrfree(trace->snaps);
  arrfree(trace->gc_const_locs);
  free(trace);
}
static trace_state *record_trace_state(vm_state *state) {
  return &state->record.trace_state;
}
static void print_record_debug(bc *pc, const char *code, vm_state *state) {
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

static trace *record_current_trace(vm_state *state) {
  return state->record.cur_trace;
}

static void record_set_current_trace(vm_state *state, trace *trace) {
  state->record.cur_trace = trace;
}

static uint32_t record_trace_count(vm_state *state) {
  return arrlen(state->record.traces);
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
    if (!trace_obj || arrlen(trace_obj->gc_const_locs) == 0) {
      continue;
    }

    bool patched = false;
    arr_for_each(trace_obj->gc_const_locs, loc) {
      if (!asm_mov64_patchable_is_live(loc)) {
        continue;
      }
      gc_obj obj = {.value = asm_read_mov64_patchable(loc)};
      if (!is_heap_object(obj)) {
        continue;
      }

      gc_obj updated = obj;
      add_root((uint64_t *)&updated, 1);
      if (updated.value == obj.value) {
        continue;
      }
      if (!patched) {
        emit_writable_begin(&record->emit_state);
        patched = true;
      }
      asm_patch_mov64_patchable(&record->emit_state, loc, updated.value);
    }
    if (patched) {
      emit_writable_end(&record->emit_state);
      __builtin___clear_cache((char *)trace_obj->code_start,
                              (char *)trace_obj->code_end);
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

static uint8_t vm_runtime_binary_result_type(ir_ins_op op, gc_obj v1,
                                             gc_obj v2) {
  gc_obj res;
  switch (op) {
  case IR_VMADD:
    res = vm_runtime_math_add_slow(v1, v2);
    break;
  case IR_VMSUB:
    res = vm_runtime_math_sub_slow(v1, v2);
    break;
  case IR_VMMUL:
    res = vm_runtime_math_mul_slow(v1, v2);
    break;
  case IR_VMDIV:
    res = vm_runtime_math_div_slow(v1, v2);
    break;
  case IR_VMQUOTIENT:
    res = vm_runtime_math_quotient_slow(v1, v2);
    break;
  case IR_VMMOD:
    res = vm_runtime_math_mod_slow(v1, v2);
    break;
  default:
    abort();
  }
  return get_type_tag(res);
}

static uint8_t vm_runtime_unary_result_type(ir_ins_op op, gc_obj v) {
  gc_obj res;
  switch (op) {
  case IR_VMINEXACT:
    res = numeric_inexact_value(v);
    break;
  case IR_VMEXACT:
    res = numeric_exact_value(v);
    break;
  case IR_VMTRUNCATE:
    res = numeric_truncate_value(v);
    break;
  default:
    abort();
  }
  return get_type_tag(res);
}

#define DEFINE_RECORD_NUMERIC_BINOP_COERCED(name, ir_fast_op, ir_vm_op)        \
  static slot emit_ov_math_##name(vm_state *state, slot v1, slot v2,           \
                                  gc_obj raw_v1, gc_obj raw_v2) {              \
    auto t = record_current_trace(state);                                      \
    uint8_t result_type =                                                      \
        vm_runtime_binary_result_type(ir_vm_op, raw_v1, raw_v2);               \
    if (slot_numeric_needs_vm(t, v1) || slot_numeric_needs_vm(t, v2) ||        \
        (result_type != FIXNUM_TAG && result_type != FLONUM_TAG)) {            \
      return add_inst(state, IR(.op = ir_vm_op, .op1 = v1, .op2 = v2,          \
                                .guard = true, .type = result_type));          \
    }                                                                          \
    if (result_type == FLONUM_TAG) {                                           \
      v1 = convert_to_flonum(state, v1);                                       \
      v2 = convert_to_flonum(state, v2);                                       \
    }                                                                          \
    return add_inst(state, IR(.op = ir_fast_op, .op1 = v1, .op2 = v2,          \
                              .type = result_type));                           \
  }

#define DEFINE_RECORD_NUMERIC_BINOP_FORCE_FLONUM(name, ir_fast_op, ir_vm_op)   \
  static slot emit_ov_math_##name(vm_state *state, slot v1, slot v2,           \
                                  gc_obj raw_v1, gc_obj raw_v2) {              \
    auto t = record_current_trace(state);                                      \
    uint8_t result_type =                                                      \
        vm_runtime_binary_result_type(ir_vm_op, raw_v1, raw_v2);               \
    if (slot_numeric_needs_vm(t, v1) || slot_numeric_needs_vm(t, v2) ||        \
        result_type != FLONUM_TAG) {                                           \
      return add_inst(state, IR(.op = ir_vm_op, .op1 = v1, .op2 = v2,          \
                                .guard = true, .type = result_type));          \
    }                                                                          \
    v1 = convert_to_flonum(state, v1);                                         \
    v2 = convert_to_flonum(state, v2);                                         \
    return add_inst(state, IR(.op = ir_fast_op, .op1 = v1, .op2 = v2,          \
                              .type = result_type));                           \
  }

#define RECORD_JEQV_GUARD_TYPE(t, v1, v2, lhs, rhs)                            \
  (((is_fixnum((lhs)) || is_flonum((lhs))) &&                                  \
    (is_fixnum((rhs)) || is_flonum((rhs))))                                    \
       ? numeric_result_type(get_slot_type((t), (v1)),                         \
                             get_slot_type((t), (v2)))                         \
       : get_slot_type((t), (v1)))

static void vm_add_snap(vm_state *state, bc *pc, uint8_t argcnt) {
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  snap sn = {
      .pc = pc,
      .offset = ts->stack_off,
      .ir = arrlen(cur_trace->ins),
      .argcnt = argcnt,
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

static void set_stack_len(trace_state *ts, uint32_t len) {
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
  return v.constant ? get_type_tag(t->consts[v.loc]) : t->ins[v.loc].type;
}

static bool ir_type_is_fix_or_flonum(uint8_t t) {
  return t == FIXNUM_TAG || t == FLONUM_TAG;
}

static bool slot_numeric_needs_vm(trace *t, slot v) {
  uint8_t ty = get_slot_type(t, v);
  return !ir_type_is_fix_or_flonum(ty);
}

static ir_ins *find_input_typecheck(trace *t, uint16_t input_loc) {
  for (size_t i = input_loc + 1; i < arrlen(t->ins); i++) {
    auto ins = &t->ins[i];
    if (ins->op == IR_TYPECHECK && !ins->op1.constant &&
        ins->op1.loc == input_loc) {
      return ins;
    }
  }
  return nullptr;
}

static void set_typecheck_guard(trace *t, uint16_t typecheck_loc) {
  auto ins = &t->ins[typecheck_loc];
  assert(ins->op == IR_TYPECHECK);
  ins->guard = true;
  if (ins->op1.constant) {
    return;
  }
  auto src = &t->ins[ins->op1.loc];
  if (src->op == IR_ARG || src->op == IR_PMOV) {
    src->guard = true;
    if (ins->type != FLONUM_TAG) {
      src->type = ins->type;
    }
  }
}

static void guard_input_value(trace *t, slot v) {
  if (v.constant) {
    return;
  }
  auto ins = &t->ins[v.loc];
  if (ins->op == IR_TYPECHECK) {
    set_typecheck_guard(t, v.loc);
    return;
  }
  ins->guard = true;
  if (ins->op != IR_ARG && ins->op != IR_PMOV) {
    return;
  }
  auto typecheck = find_input_typecheck(t, v.loc);
  if (typecheck) {
    set_typecheck_guard(t, (uint16_t)(typecheck - t->ins));
  }
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
    if (typecheck) {
      guard_input_value(record_current_trace(state), res);
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
static void set_stack_top(vm_state *state, uint8_t top) {
  trace_state *ts = record_trace_state(state);
  set_stack_len(ts, (uint32_t)top);
}
static slot const_load(vm_state *state, bc *pc, uint16_t offset) {
  // We use a non-moving gc, so this is just a runtime constant, always.
  auto c = *(gc_obj *)(pc - pc->data);
  return add_const(state, c);
}
static slot convert_to_flonum(vm_state *state, slot v1);
static slot convert_to_fixnum(vm_state *state, slot v1, gc_obj raw_v1);
DEFINE_RECORD_NUMERIC_BINOP_COERCED(add, IR_ADD, IR_VMADD)
static slot convert_to_flonum(vm_state *state, slot v1) {
  auto t = record_current_trace(state);
  auto t1 = get_slot_type(t, v1);
  if (t1 == FLONUM_TAG) {
    return v1;
  }
  if (t1 == FIXNUM_TAG) {
    if (v1.constant) {
      return add_const(state, numeric_inexact_value(t->consts[v1.loc]));
    }
    ir_ins ins = IR(.op = IR_INEXACT, .op1 = v1, .type = FLONUM_TAG);
    return add_inst(state, ins);
  }
  return add_inst(state, IR(.op = IR_VMINEXACT, .op1 = v1, .guard = true,
                            .type = FLONUM_TAG));
}
static slot convert_to_fixnum(vm_state *state, slot v1, gc_obj raw_v1) {
  auto t = record_current_trace(state);
  auto t1 = get_slot_type(t, v1);
  if (t1 == FIXNUM_TAG) {
    return v1;
  }
  if (t1 == FLONUM_TAG) {
    if (v1.constant) {
      return add_const(state, numeric_exact_value(t->consts[v1.loc]));
    }
    ir_ins ins = IR(.op = IR_EXACT, .op1 = v1, .type = FIXNUM_TAG);
    return add_inst(state, ins);
  }
  return add_inst(state,
                  IR(.op = IR_VMEXACT, .op1 = v1, .guard = true,
                     .type = vm_runtime_unary_result_type(IR_VMEXACT, raw_v1)));
}
static slot scm_truncate(vm_state *state, slot v1, gc_obj raw_v1) {
  auto t = record_current_trace(state);
  auto t1 = get_slot_type(t, v1);
  if (t1 == FIXNUM_TAG) {
    return v1;
  }
  if (t1 == FLONUM_TAG) {
    if (v1.constant) {
      return add_const(state, numeric_truncate_value(t->consts[v1.loc]));
    }
    ir_ins ins = IR(.op = IR_TRUNCATE, .op1 = v1, .type = FLONUM_TAG);
    return add_inst(state, ins);
  }
  return add_inst(
      state, IR(.op = IR_VMTRUNCATE, .op1 = v1, .guard = true,
                .type = vm_runtime_unary_result_type(IR_VMTRUNCATE, raw_v1)));
}
DEFINE_RECORD_NUMERIC_BINOP_COERCED(sub, IR_SUB, IR_VMSUB)
DEFINE_RECORD_NUMERIC_BINOP_COERCED(mul, IR_MUL, IR_VMMUL)
DEFINE_RECORD_NUMERIC_BINOP_FORCE_FLONUM(div, IR_DIV, IR_VMDIV)
DEFINE_RECORD_NUMERIC_BINOP_COERCED(quotient, IR_QUOTIENT, IR_VMQUOTIENT)
DEFINE_RECORD_NUMERIC_BINOP_COERCED(mod, IR_MOD, IR_VMMOD)

static uint8_t foreign_ir_result_type(foreign_type type) {
  switch (type) {
  case FOREIGN_TYPE_DOUBLE:
    return FLONUM_TAG;
  case FOREIGN_TYPE_UINT8:
  case FOREIGN_TYPE_INT32:
  case FOREIGN_TYPE_INT64:
  case FOREIGN_TYPE_UINT64:
    return FIXNUM_TAG;
  case FOREIGN_TYPE_STRING:
    return STRING_TAG;
  case FOREIGN_TYPE_GC_OBJ:
    return UNDEFINED_TAG;
  default:
    abort();
  }
}

static bool normalize_numeric_cmp_inputs(vm_state *state, slot *v1, slot *v2,
                                         bool require_numeric) {
  auto t = record_current_trace(state);
  auto t1 = get_slot_type(t, *v1);
  auto t2 = get_slot_type(t, *v2);
  bool n1 = (t1 == FLONUM_TAG || t1 == FIXNUM_TAG);
  bool n2 = (t2 == FLONUM_TAG || t2 == FIXNUM_TAG);
  if (!n1 || !n2) {
    if (require_numeric) {
      abort();
    }
    return false;
  }
  if (t1 == FLONUM_TAG || t2 == FLONUM_TAG) {
    *v1 = convert_to_flonum(state, *v1);
    *v2 = convert_to_flonum(state, *v2);
  }
  return true;
}

static bool ensure_recordable_foreign_sig(foreign_sig const *sig) {
  uint8_t gpr_args = 0;
  uint8_t fpr_args = 0;
  for (uint8_t i = 0; i < sig->argcnt; i++) {
    if (sig->arg_types[i] == FOREIGN_TYPE_DOUBLE) {
      fpr_args++;
    } else {
      gpr_args++;
    }
  }
  if (gpr_args > asm_foreign_call_max_gpr_args() ||
      fpr_args > asm_foreign_call_max_fpr_args()) {
    fprintf(stderr,
            "Warning: can't record FOREIGN_CALL: arg register pressure "
            "(gpr=%u fpr=%u)\n",
            gpr_args, fpr_args);
    return false;
  }
  return true;
}

static slot record_foreign_arg(vm_state *state, gc_obj *stack, uint8_t pos,
                               foreign_type type, bool *ok) {
  auto t = record_current_trace(state);
  auto arg = stack_load(state, stack, pos, true);
  auto ty = get_slot_type(t, arg);
  switch (type) {
  case FOREIGN_TYPE_DOUBLE: {
    if (ty != FIXNUM_TAG && ty != FLONUM_TAG) {
      fprintf(stderr,
              "Warning: can't record FOREIGN_CALL: arg %u expected number\n",
              pos);
      *ok = false;
      return (slot){0};
    }
    return convert_to_flonum(state, arg);
  }
  case FOREIGN_TYPE_UINT8:
  case FOREIGN_TYPE_INT32:
  case FOREIGN_TYPE_INT64:
  case FOREIGN_TYPE_UINT64:
    if (ty != FIXNUM_TAG) {
      fprintf(stderr,
              "Warning: can't record FOREIGN_CALL: arg %u expected fixnum\n",
              pos);
      *ok = false;
      return (slot){0};
    }
    return arg;
  case FOREIGN_TYPE_STRING:
    if (ty != STRING_TAG) {
      fprintf(stderr,
              "Warning: can't record FOREIGN_CALL: arg %u expected string\n",
              pos);
      *ok = false;
      return (slot){0};
    }
    return arg;
  case FOREIGN_TYPE_GC_OBJ:
    if (ty == FLONUM_TAG) {
      fprintf(stderr,
              "Warning: can't record FOREIGN_CALL: arg %u gc-obj can't be "
              "flonum\n",
              pos);
      *ok = false;
      return (slot){0};
    }
    return arg;
  default:
    fprintf(stderr,
            "Warning: can't record FOREIGN_CALL: unsupported foreign arg "
            "type\n");
    *ok = false;
    return (slot){0};
  }
}

#define DEFINE_BRANCH_CMP(name, taken_op, not_taken_op, vm_taken_op,           \
                          vm_not_taken_op, cmp_op)                             \
  static ir_ins emit_math_cmp_##name(vm_state *state, bc *pc, gc_obj *stack,   \
                                     slot v1, slot v2, bool *taken) {          \
    auto lhs = stack[pc->v1];                                                  \
    auto rhs = stack[pc->v2];                                                  \
    bool res;                                                                  \
    if (is_flonum(lhs) || is_flonum(rhs)) {                                    \
      res = numeric_to_double(lhs) cmp_op numeric_to_double(rhs);              \
    } else if (is_fixnum(lhs) && is_fixnum(rhs)) {                             \
      res = to_fixnum(lhs) cmp_op to_fixnum(rhs);                              \
    } else if ((is_fixnum(lhs) || is_bignum(lhs)) &&                           \
               (is_fixnum(rhs) || is_bignum(rhs))) {                           \
      res = numeric_exact_compare(lhs, rhs) cmp_op 0;                          \
    } else {                                                                   \
      abort();                                                                 \
    }                                                                          \
    bool fast_numeric = normalize_numeric_cmp_inputs(state, &v1, &v2, false);  \
                                                                               \
    *taken = res;                                                              \
    if (fast_numeric) {                                                        \
      return IR(.op = res ? taken_op : not_taken_op, .op1 = v1, .op2 = v2,     \
                .type = get_slot_type(record_current_trace(state), v1));       \
    }                                                                          \
    return IR(.op = res ? vm_taken_op : vm_not_taken_op, .op1 = v1, .op2 = v2, \
              .type = BOOL_TAG);                                               \
  }

DEFINE_BRANCH_CMP(lt, IR_LT, IR_GTE, IR_VMLT, IR_VMGTE, <)
DEFINE_BRANCH_CMP(gt, IR_GT, IR_LTE, IR_VMGT, IR_VMLTE, >)
DEFINE_BRANCH_CMP(lte, IR_LTE, IR_GT, IR_VMLTE, IR_VMGT, <=)
DEFINE_BRANCH_CMP(gte, IR_GTE, IR_LT, IR_VMGTE, IR_VMLT, >=)
static ir_ins emit_math_cmp_eq(vm_state *state, bc *pc, gc_obj *stack, slot v1,
                               slot v2, bool *taken, bool eqv) {
  auto lhs = stack[pc->v1];
  auto rhs = stack[pc->v2];
  auto t = record_current_trace(state);
  bool res = eqv ? obj_jeqv(lhs, rhs) : lhs.value == rhs.value;
  bool fast_numeric = normalize_numeric_cmp_inputs(state, &v1, &v2, false);
  *taken = res;
  bool lhs_numeric = is_fixnum(lhs) || is_flonum(lhs) || is_bignum(lhs);
  bool rhs_numeric = is_fixnum(rhs) || is_flonum(rhs) || is_bignum(rhs);
  if (eqv && !fast_numeric && lhs_numeric && rhs_numeric) {
    return IR(.op = res ? IR_VMJEQV : IR_VMJNEQV, .op1 = v1, .op2 = v2,
              .type = BOOL_TAG);
  }
  return IR(.op = res ? IR_EQ : IR_NE, .op1 = v1, .op2 = v2,
            .type = eqv ? RECORD_JEQV_GUARD_TYPE(t, v1, v2, lhs, rhs)
                        : get_slot_type(t, v1));
}
static void record_abort(vm_state *state, void **op_table, const char *msg) {
  if (verbose) {
    printf("Record abort: %s\n", msg);
  }
  *op_table = state->impls;
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
static void record_finish(bc *pc, vm_state *state, void **op_table,
                          const char *msg, uint8_t argcnt) {
  *op_table = state->impls;
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  if (verbose) {
    printf("Record stop %i: %s\n", cur_trace->num, msg);
  }
  vm_add_snap(state, pc, argcnt);
  box_closure_flonums(cur_trace);
  dce(cur_trace);
  cur_trace->fn =
      emit(cur_trace, &state->emit, &state->record, cur_trace->link_entry_snap);
  state->max_trace--;
  if (!cur_trace->parent_snap) {
    *cur_trace->start_ins = (bc){
        .op = OP_JFUNC,
        .data = record_trace_count(state),
    };
  }
  if (ts->poly_entry) {
    // Only install polymorphic chaining after successful recording.
    ts->poly_entry->trace->next = cur_trace;
  }
  arrput(state->record.traces, cur_trace);
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
// Nothing necessary for record - we will check in emit_snapshot - checks will
// be elided if we never hit a snapshot!
static slot build_rest_list(vm_state *state, gc_obj *stack, uint8_t start,
                            uint8_t len) {
  slot tail = add_const(state, NIL);
  for (int pos = (int)start + (int)len - 1; pos >= (int)start; pos--) {
    auto item = stack_load(state, stack, (uint8_t)pos, true);
    auto sz = add_const(state, tag_fixnum(sizeof(cons_s)));
    auto type = add_const(state, tag_fixnum(CONS_TAG));
    auto cell = add_inst(
        state, IR(.op = IR_ALLOC, .op1 = sz, .op2 = type, .type = CONS_TAG));

    auto car_ref = add_inst(state, IR(.op = IR_REF, .op1 = cell,
                                      .op2 = add_const(state, tag_fixnum(0)),
                                      .type = CONS_TAG));
    add_inst(state,
             IR(.op = IR_STORE, .op1 = car_ref, .op2 = item, .type = CONS_TAG));

    auto cdr_ref = add_inst(state, IR(.op = IR_REF, .op1 = cell,
                                      .op2 = add_const(state, tag_fixnum(1)),
                                      .type = CONS_TAG));
    add_inst(state,
             IR(.op = IR_STORE, .op1 = cdr_ref, .op2 = tail, .type = CONS_TAG));
    tail = cell;
  }
  return tail;
}
static bool check_arity(vm_state *state, gc_obj *stack, bc instr,
                        uint8_t args) {
  bool has_rest = (instr.v1 & func_flag_rest) != 0;
  if (!has_rest) {
    return args == instr.reg;
  }

  uint8_t fixed_cnt = instr.reg - 1;
  if (args < fixed_cnt) {
    return false;
  }

  set_stack(state, fixed_cnt,
            build_rest_list(state, stack, fixed_cnt, args - fixed_cnt));
  return true;
}
typedef struct {
  trace *trace;
  bool matched;
} trace_match;

static trace_match ensure_args_match_trace(vm_state *state, gc_obj *stack,
                                           trace *head, trace *cur_trace) {
  trace_match res = {.trace = head, .matched = false};

  for (trace *candidate = head; candidate; candidate = candidate->next) {
    if (verbose) {
      printf("Arg match? trace %i\n", candidate->num);
    }
    bool needs_guard[REG_ARG_CNT] = {0};
    bool match = true;
    size_t entry_ir_start = candidate->snaps[0].ir;
    size_t entry_ir_end = candidate->snaps[1].ir;
    if (arrlast(cur_trace->snaps)->argcnt != candidate->snaps[1].argcnt) {
      continue;
    }

    for (size_t i = entry_ir_start; i < entry_ir_end; i++) {
      ir_ins *ins = &candidate->ins[i];
      if (!ins->guard) {
        continue;
      }
      auto arg_idx = candidate->ins[ins->op1.loc].data;
      needs_guard[arg_idx] = true;
      if (get_type_tag(stack[arg_idx]) != ins->type) {
        match = false;
        break;
      }
    }

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
        match = false;
        break;
      }
    }
    if (!match) {
      continue;
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
          continue;
        }
        guard_input_value(cur_trace, entry->loc);
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
                                void *op_table, uint8_t argcnt) {
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
  if (pc == ts->start_ins && !is_downrec_trace(ts) &&
      (ts->depth == 0 || cnt >= 4)) {
    trace_match match =
        ensure_args_match_trace(state, stack, cur_trace, cur_trace);
    cur_trace->link = match.trace;
    cur_trace->link_entry_snap = match.matched ? 1 : 0;
    record_finish(pc, state, &op_table,
                  ts->depth != 0 ? "up-recursion" : "root loop", argcnt);
    return op_table;
  }
  if (pc != ts->start_ins && cnt >= 10) {
    record_abort(state, &op_table, "uprec detected, restart");
  }
  return op_table;
}

// Tailcall to the non-recording version, which will then tailcall the
// next *recording* opcode

PRESERVE_NONE gc_obj record(bc instr, bc *pc, gc_obj *stack, vm_state *state,
                            void *op_table, uint8_t argcnt) {
  if (verbose) {
    print_record_debug(pc, bc_names[instr.op], state);
  }

  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  if (ts->depth >= 20 || arrlen(cur_trace->ins) >= 1000) {
    record_abort(state, &op_table, "too long or too deep");
    goto done;
  }
  if (arrlen(cur_trace->consts) >= 5000) {
    record_abort(state, &op_table, "Too many consts");
    goto done;
  }

  switch (instr.op) {
    // Begin opcodes
#define RECORD_BRANCH(TAKEN, GUARD)                                            \
  do {                                                                         \
    set_stack_len(ts, pc->reg);                                                \
    auto jmp_pc = pc + 1;                                                      \
    bool taken_ = (TAKEN);                                                     \
    bc *next_pc = taken_ ? jmp_pc + 1 : jmp_pc + jmp_pc->data;                 \
    vm_add_snap(state, taken_ ? jmp_pc + jmp_pc->data : jmp_pc + 1, argcnt);   \
    add_inst(state, (GUARD));                                                  \
    vm_add_snap(state, next_pc, argcnt);                                       \
  } while (0)

#define RECORD_BIN_ARITH(OP_CODE, EMIT_FN)                                     \
  case OP_##OP_CODE: {                                                         \
    auto v1 = stack_load(state, stack, instr.v1, true);                        \
    auto v2 = stack_load(state, stack, instr.v2, true);                        \
    auto res = EMIT_FN(state, v1, v2, stack[instr.v1], stack[instr.v2]);       \
    set_stack_top(state, instr.reg + 1);                                       \
    stack_save(state, stack, instr.reg, res);                                  \
    break;                                                                     \
  }

    RECORD_BIN_ARITH(ADD, emit_ov_math_add)
    RECORD_BIN_ARITH(SUB, emit_ov_math_sub)
    RECORD_BIN_ARITH(MUL, emit_ov_math_mul)
    RECORD_BIN_ARITH(DIV, emit_ov_math_div)
    RECORD_BIN_ARITH(QUOTIENT, emit_ov_math_quotient)
    RECORD_BIN_ARITH(MOD, emit_ov_math_mod)
#undef RECORD_BIN_ARITH
  case OP_INEXACT: {
    auto v1 = stack_load(state, stack, instr.data, true);
    auto res = convert_to_flonum(state, v1);
    set_stack_top(state, instr.reg + 1);
    stack_save(state, stack, instr.reg, res);
    break;
  }
  case OP_EXACT: {
    auto v1 = stack_load(state, stack, instr.data, true);
    auto res = convert_to_fixnum(state, v1, stack[instr.data]);
    set_stack_top(state, instr.reg + 1);
    stack_save(state, stack, instr.reg, res);
    break;
  }
  case OP_TRUNCATE: {
    auto v1 = stack_load(state, stack, instr.data, true);
    auto res = scm_truncate(state, v1, stack[instr.data]);
    set_stack_top(state, instr.reg + 1);
    stack_save(state, stack, instr.reg, res);
    break;
  }
#define RECORD_BIN_CMP(OP_CODE, EMIT_FN)                                       \
  case OP_##OP_CODE: {                                                         \
    auto v1 = stack_load(state, stack, instr.v1, true);                        \
    auto v2 = stack_load(state, stack, instr.v2, true);                        \
    bool taken;                                                                \
    auto guard = EMIT_FN(state, pc, stack, v1, v2, &taken);                    \
    RECORD_BRANCH(taken, guard);                                               \
    break;                                                                     \
  }

    RECORD_BIN_CMP(JLT, emit_math_cmp_lt)
    RECORD_BIN_CMP(JGT, emit_math_cmp_gt)
    RECORD_BIN_CMP(JLTE, emit_math_cmp_lte)
    RECORD_BIN_CMP(JGTE, emit_math_cmp_gte)
  case OP_JEQ:
  case OP_JEQV: {
    auto v1 = stack_load(state, stack, instr.v1, true);
    auto v2 = stack_load(state, stack, instr.v2, true);
    bool taken;
    auto guard =
        emit_math_cmp_eq(state, pc, stack, v1, v2, &taken, instr.op == OP_JEQV);
    RECORD_BRANCH(taken, guard);
    break;
  }
#undef RECORD_BIN_CMP
  case OP_CONST: {
    auto c = const_load(state, pc, instr.data);
    stack_save(state, stack, instr.reg, c);
    break;
  }
  case OP_KSHORT: {
    gc_obj c = (gc_obj){.value = (int16_t)instr.data};
    auto c_slot = add_const(state, c);
    stack_save(state, stack, instr.reg, c_slot);
    break;
  }
  case OP_MOV: {
    auto c = stack_load(state, stack, instr.data, false);
    stack_save(state, stack, instr.reg, c);
    break;
  }
  case OP_RET: {
    auto c = stack_load(state, stack, instr.reg, false);
    // TODO: re-enable.  This needs to be a MUCH lower priority, so we
    // don't record down-rec before up-rec.  Or alternatively, maybe
    // ONLY enable down-rec recording if the function has an up-rec trace
    // already.

    /* auto res = check_record_start(pc, stack, state, op_table); */
    /* if (res != op_table) { */
    /*   op_table = res; */
    /*   instr = *pc; */
    /*   break; */
    /* } */

    bool downrec_trace = is_downrec_trace(ts);
    bool at_trace_start = (pc == ts->start_ins);

    set_stack_len(ts, instr.reg + 1);

    if (ts->depth == 0) {
      if (!cur_trace->parent_snap && !downrec_trace) {
        record_abort(state, &op_table, "return");
        instr = *pc;
        break;
      }

      int cnt = downrec_hits(ts, pc);
      bool seen_downrec = cnt > 0;

      if (cur_trace->parent_snap && seen_downrec) {
        clear_trace_state(ts);
        free_trace(cur_trace);
        record_start(state, pc, *pc, stack, argcnt);
        MUSTTAIL return record(*pc, pc, stack, state, op_table, argcnt);
      }
      if (downrec_trace && seen_downrec && at_trace_start) {
        cur_trace->link = cur_trace;
        record_finish(pc, state, &op_table, "downrec", argcnt);
        instr = *pc;
        break;
      }

      auto res = c;
      auto ra = to_return_address(stack[-1]);
      auto old_pc = ra - 1;
      auto offset = old_pc->reg + 1;

      set_stack_len(ts, 0);

      auto const_ra = add_const(state, stack[-1]);
      auto const_offset = add_const(state, tag_fixnum(offset));
      ir_ins ins = IR(.op = IR_RET, .op1 = const_offset, .op2 = const_ra,
                      .type = FIXNUM_TAG);
      add_inst(state, ins);
      set_stack(state, old_pc->reg, res);
      vm_add_snap(state, ra, argcnt);
      arrput(ts->downrec, pc);
    } else {
      ts->depth--;
      assert(ts->depth >= 0);

      auto ret = c;
      auto new_pc = to_return_address(stack[-1]);
      auto old_pc = new_pc - 1;
      ts->stack_off -= (old_pc->reg + 1);
      set_stack_len(ts, old_pc->reg + 1);
      stack_save(state, stack, old_pc->reg, ret);
    }
    break;
  }
  case OP_LOOKUP: {
    auto c = const_load(state, pc, instr.data);
    // No need to check if c is a symbol, the compiler guarantees it
    slot v1;
    {
      auto trace = record_current_trace(state);
      auto s = to_symbol(trace->consts[c.loc]);
      if (s->opt >= 0) {
        s->opt = 1;
        v1 = add_const(state, s->val);
      } else {
        ir_ins ins = IR(.op = IR_GGET, .op1 = c, .type = get_type_tag(s->val));
        v1 = add_inst(state, ins);
      }
    }
    stack_save(state, stack, instr.reg, v1);
    break;
  }
  case OP_DEFINE: {
    auto c = const_load(state, pc, instr.data);
    auto trace = record_current_trace(state);
    auto s = to_symbol(trace->consts[c.loc]);
    if (s->opt > 0) {
      record_abort(state, &op_table, "optimistic global");
      break;
    }
    auto val = stack_load(state, stack, instr.reg, false);
    ir_ins ins = IR(.op = IR_GSET, .op1 = c, .op2 = val);
    add_inst(state, ins);
    vm_add_snap(state, pc + 1, argcnt);
    break;
  }
  case OP_WRITE: {
    auto val = stack_load(state, stack, instr.v1, false);
    record_abort(state, &op_table, "can't record WRITE\n");
    break;
  }
  case OP_FUNC:
  case OP_IFUNC: {
    if (!check_arity(state, stack, instr, argcnt)) {
      break;
    }

    if (instr.op == OP_FUNC) {
      auto old_ops = op_table;
      op_table = check_record_start(pc, stack, state, op_table, argcnt);
      if (op_table != old_ops) {
        instr = *pc;
      }
    }

    break;
  }
  case OP_JFUNC: {
    // TODO argcnt check - no, will be put in trace itself!
    // LINK IT!
    instr = *pc;
    auto cur_trace = record_current_trace(state);
    // TODO can we clean this up?  side traces spawned from downrec traces
    // aren't downrec traces!
    if (is_downrec_trace(record_trace_state(state)) &&
        !cur_trace->parent_snap) {
      record_abort(state, &op_table, "can't downrec to JFUNC");
      break;
    }

    trace *target = state->record.traces[pc->data];
    trace_match match =
        ensure_args_match_trace(state, stack, target, cur_trace);
    if (cur_trace->parent_snap) {
      cur_trace->link = match.trace;
      cur_trace->link_entry_snap = match.matched ? 1 : 0;
      record_finish(pc, state, &op_table, "side trace linked to root trace",
                    argcnt);
      break;
    }

    record_abort(state, &op_table, "Root trace to JFUNC");
    instr = target->start_pc;

    break;
  }
  case OP_IF: {
    auto v = stack_load(state, stack, instr.data, false);
    bool taken = stack[instr.data].value != FALSE_REP.value;
    slot false_val = add_const(state, FALSE_REP);
    RECORD_BRANCH(taken,
                  IR(.op = taken ? IR_NE : IR_EQ, .op1 = v, .op2 = false_val));
    break;
  }
  case OP_JMP: {
    break;
  }
  case OP_CLOSURE_GET: {
    auto clo = stack_load(state, stack, instr.v1, false);
    auto clo_slot = instr.v2;
    slot res;
    if (clo.constant) {
      auto trace = record_current_trace(state);
      auto c = to_closure(trace->consts[clo.loc]);
      auto c_res = c->v[clo_slot];
      res = add_const(state, c_res);
    } else {
      slot c_pos = add_const(state, tag_fixnum(clo_slot + 1));
      gc_obj clo_obj = stack[instr.v1];
      gc_obj loaded = to_closure(clo_obj)->v[clo_slot];

      ir_ins ins = IR(.op = IR_LOAD, .op1 = clo, .op2 = c_pos,
                      .type = (uint8_t)get_type_tag(loaded));
      res = add_inst(state, ins);
    }
    stack_save(state, stack, instr.reg, res);
    break;
  }
  case OP_CLOSURE_SET: {
    auto val = stack_load(state, stack, instr.reg, false);
    auto clo = stack_load(state, stack, instr.v1, false);
    auto clo_slot = instr.v2;
    slot c_pos = add_const(state, tag_fixnum(clo_slot + 1));
    auto ref = add_inst(state, IR(.op = IR_REF, .op1 = clo, .op2 = c_pos));
    add_inst(state,
             IR(.op = IR_STORE, .op1 = ref, .op2 = val, .type = CLOSURE_TAG));
    break;
  }
  case OP_CLOSURE: {
    uint64_t capture_cnt = (uint64_t)pc->data + 1;
    uint8_t start = pc->reg;
    int64_t size_bytes =
        (int64_t)(sizeof(closure_s) + (capture_cnt * sizeof(gc_obj)));

    auto sz = add_const(state, tag_fixnum(size_bytes));
    auto type = add_const(state, tag_fixnum(CLOSURE_TAG));
    ir_ins ins =
        IR(.op = IR_ALLOC, .op1 = sz, .op2 = type, .type = CLOSURE_TAG);
    auto clo = add_inst(state, ins);

    // Initialize closure length.
    slot zero = add_const(state, tag_fixnum(0));
    slot len_off = zero;
    slot len_val = add_const(state, tag_fixnum((int64_t)capture_cnt));
    auto len_ref =
        add_inst(state, IR(.op = IR_REF, .op1 = clo, .op2 = len_off));
    add_inst(state, IR(.op = IR_STORE, .op1 = len_ref, .op2 = len_val,
                       .type = CLOSURE_TAG));

    // Seed slot 0 with the function label and zero-fill the remaining slots.
    auto label = stack_load(state, stack, start, false);
    slot c_pos = add_const(state, tag_fixnum(0 + 1));
    auto ref = add_inst(state, IR(.op = IR_REF, .op1 = clo, .op2 = c_pos));
    add_inst(state,
             IR(.op = IR_STORE, .op1 = ref, .op2 = label, .type = CLOSURE_TAG));
    for (uint64_t i = 1; i < capture_cnt; i++) {
      slot capture_pos = add_const(state, tag_fixnum((int64_t)(i + 1)));
      auto capture_ref =
          add_inst(state, IR(.op = IR_REF, .op1 = clo, .op2 = capture_pos));
      add_inst(state, IR(.op = IR_STORE, .op1 = capture_ref, .op2 = zero,
                         .type = CLOSURE_TAG));
    }

    stack_save(state, stack, instr.reg, clo);
    break;
  }
  case OP_LCALL:
  case OP_LCALLT: {
    argcnt = instr.data - 1;
    auto func = stack_load(state, stack, instr.reg, true);
    if (instr.op == OP_LCALL) {
      auto frame_top = instr.reg;
      auto ra = add_const(state, tag_return_address(pc + 1));
      stack_save(state, stack, instr.reg, ra);
      ts->stack_off += frame_top + 1;
      ts->depth++;
    } else {
      auto from = (uint16_t)(instr.reg + 1);
      auto cnt = (uint16_t)argcnt;
      // The same as the VM:
      // memmove(&stack[0], &stack[from], argcnt * sizeof(gc_obj));
      uint16_t to = 0;
      while (cnt-- > 0) {
        auto entry = stack_load(state, stack, from++, false);
        set_stack(state, to++, entry);
      }
      set_stack_len(ts, to);
    }
    if (!func.constant) {
      slot must_be = add_const(state, stack[pc->reg]);
      ir_ins ins = IR(.op = IR_EQ, .op1 = func, .op2 = must_be);
      add_inst(state, ins);
    }
    break;
  }
  case OP_APPLY: {
    auto fun = stack[pc->v1];
    const char *fname = "<non-closure>";
    if (is_closure(fun)) {
      auto code = to_closure(fun)->v[0];
      if (is_func(code)) {
        auto func = to_func(code);
        if (is_string(func->name)) {
          fname = to_string(func->name)->str;
        } else {
          fname = "<unnamed>";
        }
      } else {
        fname = "<invalid-closure-code>";
      }
    }
    char msg[256];
    snprintf(msg, sizeof(msg), "can't record APPLY (fn=%s)", fname);
    record_abort(state, &op_table, msg);
    break;
  }
  case OP_FOREIGN_CALL: {
    auto sig = stack_load(state, stack, pc->v1, false);
    auto sig_const = add_const(state, stack[pc->v1]);
    foreign_sig foreign;
    foreign_parse_sig(stack[pc->v1], &foreign);
    if (!ensure_recordable_foreign_sig(&foreign)) {
      record_abort(state, &op_table, "can't record FOREIGN_CALL signature");
      break;
    }
    auto call_argcnt = (uint8_t)(pc->v2 - 1);
    if (call_argcnt != foreign.argcnt) {
      fprintf(stderr,
              "Warning: can't record FOREIGN_CALL: arg count mismatch "
              "(bytecode=%u sig=%u)\n",
              call_argcnt, foreign.argcnt);
      record_abort(state, &op_table, "can't record FOREIGN_CALL argcnt");
      break;
    }
    if (!sig.constant) {
      add_inst(state, IR(.op = IR_EQ, .op1 = sig, .op2 = sig_const));
    }
    bool ok = true;
    slot carg = add_const(state, tag_fixnum(0));
    for (uint8_t i = call_argcnt; i > 0; i--) {
      auto arg = record_foreign_arg(state, stack, (uint8_t)(pc->v1 + i),
                                    foreign.arg_types[i - 1], &ok);
      if (!ok) {
        record_abort(state, &op_table, "can't record FOREIGN_CALL arg");
        break;
      }
      carg = add_inst(
          state, IR(.op = IR_CARG, .op1 = arg, .op2 = carg,
                    .type = get_slot_type(record_current_trace(state), arg)));
    }
    if (!ok) {
      break;
    }
    auto res =
        add_inst(state, IR(.op = IR_CCALL, .op1 = sig_const, .op2 = carg,
                           .type = foreign_ir_result_type(foreign.ret_type)));
    stack_save(state, stack, instr.reg, res);
    vm_add_snap(state, pc + 1, argcnt);
    break;
  }
  case OP_ALLOC: {
    auto sz = stack_load(state, stack, pc->v1, true);
    auto type = stack_load(state, stack, pc->v2, true);
    assert(type.constant);

    auto t = record_current_trace(state);
    auto type_const = t->consts[type.loc];
    ir_ins ins = IR(.op = IR_ALLOC, .op1 = sz, .op2 = type,
                    .type = (uint8_t)to_fixnum(type_const));
    auto obj = add_inst(state, ins);
    stack_save(state, stack, instr.reg, obj);
    break;
  }
  case OP_STORE:
  case OP_STORE_CHAR: {
    auto obj = stack_load(state, stack, pc->reg, true);
    auto val = stack_load(state, stack, pc->v1, false);
    auto offset = stack_load(state, stack, pc->v2, true);
    auto ref = add_inst(state, IR(.op = IR_REF, .op1 = obj, .op2 = offset));
    if (instr.op == OP_STORE) {
      add_inst(state,
               IR(.op = IR_STORE, .op1 = ref, .op2 = val,
                  .type = get_slot_type(record_current_trace(state), obj)));
    } else {
      add_inst(state, IR(.op = IR_STORE_CHAR, .op1 = ref, .op2 = val,
                         .type = STRING_TAG));
    }
    vm_add_snap(state, pc + 1, argcnt);
    break;
  }
  case OP_GUARD: {
    // Typecheck the object slot; SLOAD will emit the guard for us.
    stack_load(state, stack, pc->v1, true);
    auto want_tag = stack_load(state, stack, pc->v2, true);
    assert(want_tag.constant);
    bool matches = guard_obj_matches(stack[pc->v1], stack[pc->v2]);
    auto res = add_const(state, matches ? TRUE_REP : FALSE_REP);
    stack_save(state, stack, instr.reg, res);
    break;
  }
  case OP_LOAD:
  case OP_LOAD_CHAR: {
    auto obj = stack_load(state, stack, pc->v1, true);
    auto offset = stack_load(state, stack, pc->v2, true);
    auto src = stack[pc->v1];
    auto off = stack[pc->v2];
    ir_ins ins;
    if (instr.op == OP_LOAD) {
      auto base = (gc_obj *)((uint8_t *)to_raw_ptr(src) + sizeof(gc_header));
      auto type = get_type_tag(base[to_fixnum(off)]);
      ins = IR(.op = IR_LOAD, .op1 = obj, .op2 = offset, .type = type);
    } else {
      assert(is_string(src));
      assert(is_fixnum(off));
      auto str = to_string(src);
      auto idx = to_fixnum(off);
      assert(idx >= 0 && idx < to_fixnum(str->len));
      ins = IR(.op = IR_LOAD_CHAR, .op1 = obj, .op2 = offset, .type = CHAR_TAG);
    }
    auto res = add_inst(state, ins);
    stack_save(state, stack, instr.reg, res);
    break;
  }
  case OP_CHAR_INTEGER: {
    auto v1 = stack_load(state, stack, instr.v1, true);
    auto t = record_current_trace(state);
    auto ty = get_slot_type(t, v1);
    if (ty == CHAR_TAG) {
      slot res;
      if (v1.constant) {
        res = add_const(state, tag_fixnum(to_char(t->consts[v1.loc])));
      } else {
        res = add_inst(
            state, IR(.op = IR_CHAR_INTEGER, .op1 = v1, .type = FIXNUM_TAG));
      }
      stack_save(state, stack, instr.reg, res);
    } else {
      abort();
    }
    break;
  }
  case OP_INTEGER_CHAR: {
    auto v1 = stack_load(state, stack, instr.v1, true);
    auto t = record_current_trace(state);
    auto ty = get_slot_type(t, v1);
    if (ty == FIXNUM_TAG) {
      slot res;
      if (v1.constant) {
        res = add_const(state, tag_char(to_fixnum(t->consts[v1.loc])));
      } else {
        res = add_inst(state,
                       IR(.op = IR_INTEGER_CHAR, .op1 = v1, .type = CHAR_TAG));
      }
      stack_save(state, stack, instr.reg, res);
    } else {
      abort();
    }
    break;
  }
    // Nothing to record.
  case OP_ARGCNT_ERROR:
  case OP_HALT:
    break;
  case OP_CALLCC:
    record_abort(state, &op_table, "can't record CALLCC");
    break;
  case OP_CALLCC_RESUME:
    record_abort(state, &op_table, "can't record CALLCC_RESUME");
    break;
  default:
    abort();
    break;
  }
#undef RECORD_BIN_CMP
#undef RECORD_BIN_ARITH
#undef RECORD_BRANCH
done:
  op_func impl = state->impls[instr.op];
  MUSTTAIL return impl(instr, pc, stack, state, op_table, argcnt);
}

// End opcodes

static trace *record_begin_trace(vm_state *state, bc *pc, bc instr) {
  record_set_current_trace(state, calloc(1, sizeof(trace)));
  trace *cur_trace = record_current_trace(state);
  cur_trace->start_ins = pc;
  cur_trace->start_pc = instr;
  cur_trace->num = record_trace_count(state);
  trace_state *ts = record_trace_state(state);
  memset(ts, 0, sizeof(trace_state));
  ts->start_ins = pc;
  ts->start_is_ret = (instr.op == OP_RET);
  return cur_trace;
}

static void record_seed_entry_args(vm_state *state, bc *pc, bc instr,
                                   gc_obj *stack, uint8_t argcnt) {
  trace_state *ts = record_trace_state(state);
  // OK! Let's put function arguments in registers.
  // Note these *must* be marked as 'changed', since ARGS aren't saved between
  // trace loops at all.
  assert(instr.op == OP_FUNC || instr.op == OP_RET);
  switch (instr.op) {
  case OP_FUNC:
    for (int i = 0; i < MIN(instr.reg, REG_ARG_CNT); i++) {
      uint8_t type = get_type_tag(stack[i]);
      set_stack(state, i,
                add_inst(state, IR(.op = IR_ARG, .data = i,
                                   .type = type == FLONUM_TAG ? UNDEFINED_TAG
                                                              : type)));
    }
    break;
  case OP_RET:
    uint8_t type = get_type_tag(stack[instr.reg]);
    set_stack(
        state, instr.reg,
        add_inst(state, IR(.op = IR_ARG, .data = instr.reg,
                           .type = type == FLONUM_TAG ? UNDEFINED_TAG : type)));

    break;
  default:
    abort();
  }
  vm_add_snap(state, pc, argcnt);
  // Typecheck entry arguments up-front so flonums can target the checked
  // value.
  switch (instr.op) {
  case OP_FUNC:
    for (int i = 0; i < MIN(instr.reg, REG_ARG_CNT); i++) {
      auto s = get_sentry(state, i);
      uint8_t type = get_type_tag(stack[i]);
      auto checked =
          add_inst(state, IR(.op = IR_TYPECHECK, .op1 = s->loc, .type = type));
      if (type == FLONUM_TAG) {
        set_stack(state, i, checked);
      }
    }
    break;
  case OP_RET: {
    auto s = get_sentry(state, instr.reg);
    uint8_t type = get_type_tag(stack[instr.reg]);
    auto checked =
        add_inst(state, IR(.op = IR_TYPECHECK, .op1 = s->loc, .type = type));
    if (type == FLONUM_TAG) {
      set_stack(state, instr.reg, checked);
    }
    break;
  }
  default:
    abort();
  }
  vm_add_snap(state, pc, argcnt);
  ts->start_record_size = arrlen(record_current_trace(state)->ins);
}

void record_start(vm_state *state, bc *pc, bc instr, gc_obj *stack,
                  uint8_t argcnt) {

  if (verbose) {
    const char *fname = func_name_from_pc(pc);
    printf("Record start %p %i %s %s\n", pc, record_trace_count(state), fname,
           instr.op == OP_RET ? "DOWNREC" : "");
  }
  record_begin_trace(state, pc, instr);
  trace_state *ts = record_trace_state(state);
  record_current_trace(state)->kind = TRACE_ROOT;
  ts->poly_entry = nullptr;
  record_seed_entry_args(state, pc, instr, stack, argcnt);
}

void record_start_poly(vm_state *state, bc *pc, bc instr, gc_obj *stack,
                       snap *side_snap, uint8_t argcnt) {
  if (verbose) {
    printf("Record start poly %i\n", record_trace_count(state));
  }
  assert(instr.op != OP_JFUNC);
  record_begin_trace(state, pc, instr);
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  cur_trace->kind = TRACE_POLY;
  cur_trace->parent_snap = side_snap;
  ts->depth = side_snap->depth;
  ts->poly_entry = side_snap;
  record_seed_entry_args(state, pc, instr, stack, argcnt);
}

static bool replay_parent_guard(snap *side_snap, ir_ins const *old_ins) {
  bool use_prev_guard = side_snap == &side_snap->trace->snaps[0] &&
                        side_snap->trace->kind == TRACE_SIDE;
  return use_prev_guard ? old_ins->prev_guard : old_ins->guard;
}

void record_start_side(vm_state *state, bc *pc, bc instr, gc_obj *stack,
                       snap *side_snap, uint8_t argcnt) {
  if (verbose) {
    printf("Record start side %i\n", record_trace_count(state));
  }
  assert(instr.op != OP_JFUNC);
  record_begin_trace(state, pc, instr);
  trace_state *ts = record_trace_state(state);
  trace *cur_trace = record_current_trace(state);
  cur_trace->kind = TRACE_SIDE;
  cur_trace->parent_snap = side_snap;
  ts->depth = side_snap->depth;
  ts->poly_entry = nullptr;

  // Replay snapshot loads, so we keep things in register.
  size_t parent_ins_len = arrlen(side_snap->trace->ins);
  slot *pmov_by_parent_id = malloc(parent_ins_len * sizeof(slot));
  assert(pmov_by_parent_id != NULL || parent_ins_len == 0);
  for (size_t i = 0; i < parent_ins_len; i++) {
    pmov_by_parent_id[i] = (slot){.constant = true, .loc = 0};
  }
  arr_for_each_idx(side_snap->slots, j) {
    auto entry = &side_snap->slots[j];
    if (entry->val.constant) {
      set_stack(state, entry->slot,
                add_const(state, side_snap->trace->consts[entry->val.loc]));
    } else {
      uint16_t parent_id = entry->val.loc;
      slot pmov = pmov_by_parent_id[parent_id];
      if (pmov.constant) {
        auto old_ins = &side_snap->trace->ins[parent_id];
        bool old_guard = replay_parent_guard(side_snap, old_ins);
        ir_ins pmov_ins =
            IR(.op = IR_PMOV, .prev_reg = old_ins->reg, .prev_guard = old_guard,
               .guard = old_guard, .type = old_ins->type);
        if (old_ins->spill != SPILL_NONE) {
          pmov_ins.spill = old_ins->spill;
        } else {
          pmov_ins.reg = old_ins->reg;
        }
        pmov = add_inst(state, pmov_ins);
        pmov_by_parent_id[parent_id] = pmov;
      }
      set_stack(state, entry->slot, pmov);
    }
  }
  free(pmov_by_parent_id);
  // We set this last, since snapshots have absolute indexs, and set_stack is
  // relative to stack_off.
  ts->stack_off = side_snap->offset;
  vm_add_snap(state, pc, argcnt);

  // Insert initial typechecks for replayed values.
  arr_for_each_idx(side_snap->slots, j) {
    auto entry = &side_snap->slots[j];
    if (entry->val.constant) {
      continue;
    }
    auto s = get_sentry_abs(state, entry->slot);
    auto old_ins = &side_snap->trace->ins[entry->val.loc];
    int64_t rel_slot = (int64_t)entry->slot - (int64_t)ts->stack_off;
    if (replay_parent_guard(side_snap, old_ins) ||
        old_ins->type == FLONUM_TAG) {
      // Already typechecked.
      continue;
    }
    uint8_t type = get_type_tag(stack[rel_slot]);
    auto checked =
        add_inst(state, IR(.op = IR_TYPECHECK, .op1 = s->loc, .type = type));
    if (type == FLONUM_TAG) {
      set_stack_abs(state, entry->slot, checked);
    }
  }
  vm_add_snap(state, pc, argcnt);
  ts->start_record_size = arrlen(record_current_trace(state)->ins);
}

void free_traces(struct vm_state *state) {
  auto rs = &state->record;
  arr_for_each(rs->traces, trace) { free_trace(trace); }
  arrfree(rs->traces);
  if (rs->cur_trace) {
    free_trace(rs->cur_trace);
  }
  clear_trace_state(&rs->trace_state);
  hm_free(rs->blacklist);
  rs->cur_trace = nullptr;
}
