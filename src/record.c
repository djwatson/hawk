// Copyright 2023 Dave Watson

#include "record.h"

#include <assert.h> // for assert
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h> // for uint32_t
#include <stdio.h>  // for printf
#include <stdlib.h> // for exit
#include <string.h> // for NULL, memmove, size_t

#include "asm_x64.h"  // for REG_NONE, asm_jit, reg_names
#include "bytecode.h" // for INS_A, INS_B, INS_OP, INS_C, INS_D, bcfunc
#include "defs.h"
#include "ir.h" // for ir_ins, trace_s, ir_ins_op, ir_ins::(anonymous...
#include "opcodes.h"
#include "snap.h" // for add_snap, snap_replay
#include "third-party/stb_ds.h"
#include "trace_dump.h"
#include "types.h" // for CONS_TAG, FALSE_REP, SYMBOL_TAG, symbol, CLOSU...
#include "vm.h"    // for find_func_for_frame, hotmap_mask, hotmap_sz

#define auto __auto_type
#define nullptr NULL

extern bool verbose;

typedef struct {
  uint32_t *pc;
  uint32_t cnt;
} blacklist_entry;

#define BLACKLIST_MAX 64
#define BLACKLIST_SZ 512

blacklist_entry blacklist[BLACKLIST_SZ];
uint32_t blacklist_slot = 0;

void opt_loop(trace_s *trace, int *regs);

unsigned int *pc_start;
unsigned int instr_count;
int depth = 0;

uint16_t max_slot3(uint32_t i) {
  uint16_t a = INS_A(i);
  uint16_t b = INS_B(i);
  uint16_t c = INS_C(i);
  if (a > b) {
    if (a > c) {
      return a;
    }
    return c;
  }
  if (b > c) {
    return b;
  }
  return c;
}

bcfunc *func;
uint16_t regs_list[257];
uint16_t *regs = &regs_list[1];
snap_s *side_exit = nullptr;
static trace_s *parent = nullptr;
static uint8_t unroll = 0;
typedef struct {
  uint32_t *key;
  uint32_t value;
} tailcall_counter;
static tailcall_counter *tailcalled = nullptr;
static uint32_t stack_top;

unsigned int **downrec = NULL;

typedef enum trace_state_e {
  OFF = 0,
  START,
  TRACING,
} trace_state_e;

trace_state_e trace_state = OFF;
trace_s *trace = nullptr;
trace_s **traces = nullptr;

unsigned int *patchpc = nullptr;
unsigned int patchold;

uint32_t find_penalty_pc(const uint32_t *pc) {
  for (uint32_t i = 0; i < blacklist_slot; i++) {
    if (blacklist[i].pc == pc) {
      return blacklist[i].cnt;
    }
  }
  return 0;
}

void penalty_pc(uint32_t *pc) {
  uint32_t i = 0;
  for (; i < blacklist_slot; i++) {
    if (blacklist[i].pc != pc) {
      continue;
    }
    if (blacklist[i].cnt >= BLACKLIST_MAX) {
      if (verbose) {
        printf("Blacklist pc %p\n", pc);
      }
      if (INS_OP(*pc) == FUNC) {
        *pc = ((*pc) & ~0xff) + IFUNC;
      } else if (INS_OP(*pc) == FUNCV) {
        *pc = ((*pc) & ~0xff) + IFUNCV;
      } else if (INS_OP(*pc) == CLFUNC) {
        *pc = ((*pc) & ~0xff) + ICLFUNC;
      } else if (INS_OP(*pc) == CLFUNCV) {
        *pc = ((*pc) & ~0xff) + ICLFUNCV;
      } else if (INS_OP(*pc) == LOOP) {
        *pc = ((*pc) & ~0xff) + ILOOP;
      } else if (INS_OP(*pc) == JLOOP) {
        auto startpc = trace_cache_get(INS_D(*pc))->startpc;
        if (INS_OP(startpc) == LOOP) {
          trace_cache_get(INS_D(*pc))->startpc = (startpc & ~0xff) + ILOOP;
        } else {
          trace_cache_get(INS_D(*pc))->startpc = (startpc & ~0xff) + IRET1;
        }
      } else if (INS_OP(*pc) == JFUNC) {
        auto ctrace = trace_cache_get(INS_D(*pc));
        auto op = ctrace->startpc & 0xff;
        auto oldpc = ctrace->startpc & ~0xff;
        if (op == FUNC) {
          ctrace->startpc = oldpc + IFUNC;
        } else if (op == CLFUNC) {
          ctrace->startpc = oldpc + ICLFUNC;
        } else if (op == FUNCV) {
          ctrace->startpc = oldpc + IFUNCV;
        } else if (op == CLFUNCV) {
          ctrace->startpc = oldpc + ICLFUNCV;
        }
      } else if (INS_OP(*pc) == RET1) {
        *pc = ((*pc) & ~0xff) + IRET1;
      } else {
        printf("Could not blacklist %s\n", ins_names[INS_OP(*pc)]);
        exit(-1);
      }
      int64_t next = i + 1;
      while (next < blacklist_slot) {
        blacklist_entry tmp = blacklist[next];
        blacklist[next - 1] = blacklist[next];
        blacklist[next] = tmp;
        next++;
      }
      blacklist_slot--;
    } else {
      blacklist[i].cnt++;
      int64_t prev = (int64_t)i - 1;
      while (prev >= 0 && blacklist[prev].cnt <= blacklist[prev + 1].cnt) {
        blacklist_entry tmp = blacklist[prev];
        blacklist[prev] = blacklist[prev + 1];
        blacklist[prev + 1] = tmp;
        prev--;
      }
    }
    return;
  }

  // Didn't find it, add it to the list.
  if (i < BLACKLIST_SZ) {
    blacklist[i].pc = pc;
    blacklist[i].cnt = 1;
    blacklist_slot++;
  } else {
    if (verbose) {
      printf("BLACKLIST EVICT\n");
    }
    blacklist[BLACKLIST_SZ - 1].pc = pc;
    blacklist[BLACKLIST_SZ - 1].cnt = 1;
  }
}

void pendpatch() {
  if (patchpc != nullptr) {
    // printf("PENDPACTCH\n");
    *patchpc = patchold;
    patchpc = nullptr;
  }
}

void trace_flush(trace_s *ctrace_start, bool all) {
  trace_s **q = NULL;
  arrput(q, ctrace_start);
  while (arrlen(q)) {
    auto ctrace = arrpop(q);
    *ctrace->start = ctrace->startpc;
    for (uint32_t i = 0; i < arrlen(ctrace->syms); i++) {
      auto csym = ctrace->syms[i];
      symbol *sym = to_symbol(ctrace->consts[csym]);
      // printf("Flushing from sym %s trace %i\n",
      // ((string_s*)(sym->name-PTR_TAG))->str, ctrace->num);
      (void)hmdel(sym->lst, ctrace->num);
    }
    arrfree(ctrace->syms);
    for (uint32_t i = 0; i < arrlen(ctrace->func_opts); i++) {
      auto fun = ctrace->func_opts[i];
      (void)hmdel(fun->lst, ctrace->num);
    }
    arrfree(ctrace->func_opts);
    if (ctrace->parent) {
      auto p = ctrace->parent;
      ctrace->parent = NULL;
      arrput(q, p);
    }
    if (ctrace->next) {
      auto v = ctrace->next;
      ctrace->next = NULL;
      arrput(q, v);
    }
    if (all) {
      for (int32_t i = 0; i < arrlen(traces); i++) {
        if (traces[i]->link == ctrace->num && traces[i] != ctrace) {
          traces[i]->link = -1;
          arrput(q, traces[i]);
        }
      }
    }
  }
  arrfree(q);
  // TODO(djwatson): also free trace.
}

void record_side(trace_s *p, snap_s *side) {
  parent = p;
  side_exit = side;
}

void record_abort();
void record_start(uint32_t *pc, gc_obj *frame, int64_t argcnt) {
  hmdefault(tailcalled, 0);
  trace = malloc(sizeof(trace_s));
  trace->syms = NULL;
  trace->func_opts = NULL;
  trace->next = NULL;
  trace->ops = NULL;
  trace->consts = NULL;
  trace->relocs = NULL;
  trace->snaps = NULL;
  trace->link = -1;
  trace->startpc = *pc;
  trace->start = pc;
  trace->num = arrlen(traces);
  trace->fn = NULL;
  trace->parent = parent;
  trace_state = START;
  unroll = 0;
  if (verbose) {
    func = find_func_for_frame(pc);
    assert(func);
    printf("Record start %i at %s func %s\n", trace->num,
           ins_names[INS_OP(*pc)], func->name);
    if (parent != nullptr) {
      printf("Parent %i exit ir %i\n", parent->num, side_exit->ir);
    }
  }
  pc_start = pc;
  instr_count = 0;
  depth = 0;
  regs = &regs_list[1];
  memset(regs_list, 0xff, sizeof(regs_list)); // memset to -1.

  stack_top = INS_A(*pc);
  if (INS_OP(*pc) == LOOP || INS_OP(*pc) == ILOOP) {
    stack_top = INS_A(*pc) + INS_B(*pc);
  } else if (INS_OP(*pc) == FUNCV || INS_OP(*pc) == IFUNCV ||
             INS_OP(*pc) == ICLFUNCV || INS_OP(*pc) == CLFUNCV) {
    stack_top = argcnt;
  } else if (INS_OP(*pc) == RET1) {
    stack_top = INS_A(*pc) + 1;
  }

  if (side_exit != nullptr) {
    stack_top = snap_replay(&regs, side_exit, parent, trace, &depth);
  }
  auto next_pc = pc;
  if (INS_OP(*pc) == FUNC || INS_OP(*pc) == LOOP || INS_OP(*pc) == FUNCV) {
    next_pc = pc + 1;
  }
  if (INS_OP(*pc) == CLFUNC || INS_OP(*pc) == CLFUNCV) {
    next_pc = pc + 2;
  }
  if (!parent) {
    if (INS_OP(*pc) == FUNC || INS_OP(*pc) == IFUNC || INS_OP(*pc) == CLFUNC ||
        INS_OP(*pc) == ICLFUNC) {
      for (unsigned arg = 0; arg < INS_A(*pc); arg++) {
        if (arg >= 6) {
          // TODO(djwatson) clean this up in the register allocator.
          break;
        }
        regs[arg] = push_ir(trace, IR_ARG, arg, 0,
                            get_object_ir_type(frame[arg]) | IR_INS_TYPE_GUARD);
      }
    }
    if (INS_OP(*pc) == LOOP) {
      for (unsigned arg = INS_A(*pc); arg < INS_A(*pc) + INS_B(*pc); arg++) {
        if (arg - INS_A(*pc) >= 6) {
          // TODO(djwatson) clean this up in the register allocator.
          break;
        }
        regs[arg] = push_ir(trace, IR_ARG, arg, 0,
                            get_object_ir_type(frame[arg]) | IR_INS_TYPE_GUARD);
      }
    }
  }
  add_snap(regs_list, (int32_t)(regs - regs_list - 1), trace, next_pc, depth,
           stack_top);
}

extern int joff;
extern unsigned TRACE_MAX;

static void record_stop(uint32_t *pc, int link) {
  auto offset = regs - regs_list - 1;
  add_snap(regs_list, offset, trace, pc, depth, stack_top);
  /* if (link == (int)arrlen(traces) && offset == 0) {
    // Attempt to loop-fiy it.
    opt_loop(trace, regs);
  }
*/

  // if (arrlen(trace->ops) <= 3) {
  //   printf("Record abort: trace too small\n");
  //   record_abort();
  //   return;
  // }

  pendpatch();
  hmfree(tailcalled); //!OCLINT

  if (side_exit) {
    if (verbose) {
      printf("Hooking to parent trace\n");
    }
  } else {
    auto op = INS_OP(*pc_start);
    if (op == JFUNC || op == JLOOP) {
      auto prev = trace_cache_get(INS_D(*pc_start));
      trace->next = prev->next;
      prev->next = trace;
    } else if (op != RET1 && op != LOOP) {
      *pc_start = CODE_D(JFUNC, INS_A(*pc_start), arrlen(traces));
      if (verbose) {
        printf("Installing JFUNC\n");
      }
    } else {
      *pc_start = CODE_D(JLOOP, 0, arrlen(traces));
      if (verbose) {
        printf("Installing JLOOP\n");
      }
    }
  }
  if (verbose) {
    printf("Installing trace %li\n", arrlen(traces));
  }

  trace->link = link;
  arrput(traces, trace);

  // dump_trace(trace);
  asm_jit(trace, side_exit, parent);
  if (verbose) {
    dump_trace(trace);
  }

  trace_state = OFF;
  side_exit = nullptr;
  arrfree(downrec);
  trace = nullptr;
  parent = nullptr;
}

void record_abort() {
  if (!parent) {
    penalty_pc(pc_start);
  }
  for (uint32_t i = 0; i < arrlen(trace->syms); i++) {
    uint16_t csym = trace->syms[i];
    symbol *sym = to_symbol(trace->consts[csym]);
    (void)hmdel(sym->lst, trace->num);
  }
  arrfree(trace->syms);
  for (uint32_t i = 0; i < arrlen(trace->func_opts); i++) {
    auto f = trace->func_opts[i];
    (void)hmdel(f->lst, trace->num);
  }
  arrfree(trace->func_opts);
  // TODO(djwatson) separate func
  for (uint64_t i = 0; i < arrlen(trace->snaps); i++) {
    free_snap(&trace->snaps[i]);
  }
  arrfree(trace->consts);
  arrfree(trace->relocs);
  arrfree(trace->ops);
  arrfree(trace->snaps);
  hmfree(tailcalled); //!OCLINT

  pendpatch();
  free(trace);
  trace = nullptr;
  trace_state = OFF;
  side_exit = nullptr;
  arrfree(downrec);
  parent = nullptr;
}

bool record(uint32_t *pc, gc_obj *frame, int64_t argcnt) {
  if (arrlen(traces) >= TRACE_MAX) {
    return true;
  }
  switch (trace_state) {
  case OFF: {
    // TODO(djwatson) fix?
    if ((INS_OP(*pc) == JFUNC || INS_OP(*pc) == JLOOP) &&
        side_exit == nullptr) {
      patchpc = pc;
      patchold = *pc;
      *pc = traces[INS_D(*pc)]->startpc;
      /* printf("CAN'T RECORD TO JFUNC\n"); */
      /* exit(-1); */
      /* return 1; */
      // Recording different trace
    }
    record_start(pc, frame, argcnt);
    auto res = record_instr(pc, frame, argcnt);
    if (trace_state == START) {
      trace_state = TRACING;
    }
    return res;
  }
  case TRACING: {
    pendpatch();
    return record_instr(pc, frame, argcnt);
  }
  default:
  case START: {
    printf("BAD TRACE STATE %i\n", trace_state);
    exit(-1);
    return true;
  }
  }
}

// Convert a runtime object type to an IR type.
// Use tag bits.  If it's a literal, use IMMEDIATE_MASK.
// If it's a PTR_TAG, follow ptr and use tag bits there.
//
// Currently depends on tag being less than 7 bits total.
// TODO(djwatson) top bit is IR_INS_TYPE_GUARD, this should be part
//      of the load instruction instead.
// TODO(djwatson): for records we may need a different strategy.
uint8_t get_object_ir_type(gc_obj obj) {
  if (is_ptr(obj)) {
    return get_ptr_tag(obj);
  }
  if (is_literal(obj)) {
    return get_imm_tag(obj);
  }
  return get_tag(obj);
}

uint16_t record_stack_load(uint16_t slot, const gc_obj *frame) {
  if (regs[slot] == REGS_NONE) {
    // Guard on type
    auto type = get_object_ir_type(frame[slot]);

    regs[slot] =
        push_ir(trace, IR_SLOAD, slot, IR_NONE, IR_INS_TYPE_GUARD | type);
  }
  return regs[slot];
}

// Note: Does not add snap after!  Add if not at end of trace.
void record_funcv(uint32_t i, uint32_t *pc, gc_obj *frame, int64_t argcnt) {
  // Otherwise we're on-trace, and the last IR was a call.
  auto ra = INS_A(i);
  auto cnt = argcnt - ra;
  // Build a list from ra of cnt length.

  // Load everything first, so that we don't get a guard failure
  // before alloc.

  // TODO(djwatson): when typechecks are lazy, this can be done
  // inline, since it's just stored in a list and doesn't need a
  // typecheck.
  uint16_t *locs = NULL; // NOLINT
  for (uint32_t j = ra + cnt - 1; j >= ra; j--) {
    arrput(locs, record_stack_load(j, frame));
  }
  stack_top = argcnt;
  add_snap(regs_list, regs - regs_list - 1, trace, pc, depth, stack_top);
  trace->snaps[arrlen(trace->snaps) - 1].argcnt = argcnt;
  // TODO(djwatson) this forces a side exit without recording.  Put GC
  // inline in generated code?  Would have to flush all registers to
  // stack.
  trace->snaps[arrlen(trace->snaps) - 1].exits = 255;

  // Build the list.
  auto knum = arrlen(trace->consts);
  arrput(trace->consts, NIL);
  uint16_t prev = knum | IR_CONST_BIAS;
  for (uint32_t j = 0; j < cnt; j++) {
    knum = arrlen(trace->consts);
    arrput(trace->consts, tag_fixnum(sizeof(cons_s)));
    auto cell =
        push_ir(trace, IR_ALLOC, knum | IR_CONST_BIAS, CONS_TAG, CONS_TAG);
    auto ref = push_ir(trace, IR_REF, cell, 8 - CONS_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, locs[j], UNDEFINED_TAG); // NOLINT
    ref = push_ir(trace, IR_REF, cell, 8 + 8 - CONS_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, prev, UNDEFINED_TAG);
    prev = cell;
  }
  regs[INS_A(i)] = prev;
  stack_top = INS_A(i) + 1;
  arrfree(locs);
}

static void check_emit_funcv(uint32_t startpc, uint32_t *pc, gc_obj *frame,
                             int64_t argcnt) {
  if (INS_OP(startpc) == FUNCV || INS_OP(startpc) == CLFUNCV) {
    stack_top = argcnt;
    record_funcv(startpc, pc, frame, argcnt);
  }
}

static trace_s *check_argument_match(trace_s *pt) {
  auto ptrace = pt;
  while (ptrace) {
    bool found = true;
    for (uint64_t i = 0; i < arrlen(ptrace->ops); i++) {
      auto op = &ptrace->ops[i];
      if (op->op != IR_ARG) {
        break;
      }
      assert(regs[op->op1] != REGS_NONE);
      uint8_t typ;
      if (ir_is_const(regs[op->op1])) {
        typ = get_object_ir_type(trace->consts[regs[op->op1] - IR_CONST_BIAS]);
      } else {
        typ = trace->ops[regs[op->op1]].type;
      }
      if (get_type(typ) != get_type(op->type)) {
        found = false;
        break;
      }
    }
    if (found) {
      return ptrace;
    }
    ptrace = ptrace->next;
  }
  return NULL;
}

static bool do_compare(uint8_t op, gc_obj v1o, gc_obj v2o) {
  auto v1 = v1o.value;
  auto v2 = v2o.value;
  switch (op) {
    // TODO(djwatson) these got swapped in the BC emitter on accident.
  case JISF:
    return v1 != FALSE_REP.value;
  case JIST:
    return v1 == FALSE_REP.value;
  case ISLT:
  case JISLT:
    return v1 < v2;
  case ISLTE:
  case JISLTE:
    return v1 <= v2;
  case ISGTE:
  case JISGTE:
    return v1 >= v2;
  case ISGT:
  case JISGT:
    return v1 > v2;
  case JEQ:
  case EQ:
    return v1 == v2;
  case JNEQ:
    return v1 != v2;
  default:
    abort();
    break;
  }
}

static int record_comp2(uint8_t bc, uint8_t true_op, uint8_t false_op,
                        uint8_t a, uint8_t b, uint8_t c, gc_obj *frame) {
  uint32_t op1 = record_stack_load(b, frame);
  uint32_t op2 = record_stack_load(c, frame);
  auto v1 = frame[b];
  auto v2 = frame[c];
  if (get_object_ir_type(v1) == FLONUM_TAG ||
      get_object_ir_type(v2) == FLONUM_TAG) {
    if (verbose) {
      printf("Record abort: flonum not supported in islt\n");
    }
    record_abort();
    return 1;
  }
  auto constant = FALSE_REP;
  uint8_t op = false_op;
  bool result = do_compare(bc, frame[b], frame[c]);

  if (result) {
    constant = TRUE_REP;
    op = true_op;
  }
  auto knum = arrlen(trace->consts);
  arrput(trace->consts, constant);
  push_ir(trace, op, op1, op2, BOOL_TAG);
  regs[a] = IR_CONST_BIAS + knum;
  stack_top = a;
  return 0;
}

static bool record_jcomp2(uint8_t bc, uint8_t true_op, uint8_t false_op,
                          uint8_t b, uint8_t c, gc_obj *frame, uint32_t *pc,
                          bool typecheck) {
  uint32_t *next_pc;
  ir_ins_op op;
  bool result = do_compare(bc, frame[b], frame[c]);
  uint8_t type;
  uint32_t op1 = record_stack_load(b, frame);
  uint32_t op2 = record_stack_load(c, frame);
  if (op1 >= IR_CONST_BIAS) {
    type = get_tag(trace->consts[op1 - IR_CONST_BIAS]);
  } else {
    type = get_type(trace->ops[op1].type);
  }
  if (typecheck && type != 0) {
    if (verbose) {
      printf("Record abort: Only int supported in trace: %i\n", type);
    }
    record_abort();
    return true;
  }
  stack_top = INS_A(*pc);
  if (result) {
    op = true_op;
    add_snap(regs_list, regs - regs_list - 1, trace, pc + INS_D(*(pc + 1)) + 1,
             depth, stack_top);
    next_pc = pc + 2;
  } else {
    op = false_op;
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 2, depth, stack_top);
    next_pc = pc + INS_D(*(pc + 1)) + 1;
  }
  push_ir(trace, op, op1, op2, type);
  add_snap(regs_list, regs - regs_list - 1, trace, next_pc, depth, stack_top);
  return false;
}

static void record_jcomp1(uint8_t bc, uint8_t true_op, uint8_t false_op,
                          uint8_t b, uint8_t c, gc_obj *frame, uint32_t *pc) {
  auto knum = arrlen(trace->consts);
  arrput(trace->consts, FALSE_REP);
  record_jcomp2(bc, true_op, false_op, b, c, frame, pc, false);
  trace->ops[arrlen(trace->ops) - 1].op2 = knum | IR_CONST_BIAS;
}

extern uint8_t hotmap[hotmap_sz];
bool record_instr(uint32_t *pc, gc_obj *frame, int64_t argcnt) {
  unsigned int i = *pc;

  if (instr_count > 4000) {
    if (verbose) {
      printf("Record abort: due to length\n");
    }
    record_abort();
    return true;
  }
  // TODO(djwatson) this should check regs depth
  if (depth >= 20) {
    if (verbose) {
      printf("Record abort: (stack too deep)\n");
    }
    record_abort();
    return true;
  }

  instr_count++;
  if (verbose) {
    for (int j = 0; j < depth; j++) {
      printf(" . ");
    }
    printf("%p %s %i %i %i\n", pc, ins_names[INS_OP(i)], INS_A(i), INS_B(i),
           INS_C(i));
  }
  switch (INS_OP(i)) {
  case ILOOP: {
    stack_top = INS_A(i) + INS_B(i);
    break;
  }
  case LOOP: {
    stack_top = INS_A(i) + INS_B(i);
    if ((pc == pc_start) && (depth == 0) && (trace_state == TRACING) &&
        INS_OP(trace->startpc) != RET1 && parent == nullptr) {
      auto link_trace = check_argument_match(trace);
      if (link_trace) {
        if (verbose) {
          printf("Record stop loop\n");
        }
        record_stop(pc, link_trace->num);
        return true;
      }
    }
    if ((trace_state != START) && (!parent || (unroll++ >= 3))) {
      // TODO(djwatson) check the way luajit does it
      if (parent) {
        if (verbose) {
          printf("Record abort: Unroll limit reached in loop for side trace\n");
        }
      } else {
        if (verbose) {
          printf("Record abort: Root trace hit untraced loop\n");
        }
      }
      hotmap[hotmap_hash(pc)] = 1;
      record_abort();
      return true;
    }
    break;
  }
  case CLFUNCV:
  case FUNCV: {
    // Fallthrough
    if (argcnt < INS_A(*pc)) {
      break;
    }
    stack_top = argcnt;
    // If this isn't the trace start, we need to package any varargs.
    if (trace_state != START) {
      record_funcv(i, pc, frame, argcnt);
      if (INS_OP(i) == CLFUNCV) {
        add_snap(regs_list, regs - regs_list - 1, trace, pc + 2, depth,
                 stack_top);
      } else {
        add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth,
                 stack_top);
      }
    }
    __attribute__((fallthrough));
  }
  case ICLFUNC:
  case CLFUNC: {
    if (((INS_OP(i) == ICLFUNC) || (INS_OP(i) == CLFUNC)) &&
        (argcnt != INS_A(*pc))) {
      break;
    }
    __attribute__((fallthrough));
  }
  case IFUNC:
  case FUNC: {
    stack_top = INS_A(i);
    // Check for unroll.
    int64_t cnt = 0;
    auto p_pc = to_return_address(frame[-1]);
    auto ret_pc = p_pc;
    auto pframe = frame;
    for (auto d = depth - 1; d > 0; d--) {
      pframe -= (INS_A(*(p_pc - 1)) + 1);
      p_pc = to_return_address(pframe[-1]);
      if (p_pc == ret_pc) {
        cnt++;
      }
    }

    // A pile of heuristics, to try and catch traces that are loops, but don't
    // use the loop construct.
    if (pc == pc_start && parent == NULL) {
      if ((hmget(tailcalled, pc)) >= UNROLL_LIMIT && depth == 0) {
        auto link_trace = check_argument_match(trace);
        if (link_trace) {
          if (verbose) {
            printf("Record stop loop\n");
          }
          record_stop(pc, link_trace->num);
          return true;
        }
      } else if (cnt > UNROLL_LIMIT && depth != 0) {
        // Don't test on 'tailcalled' here, since up-recursion
        // can't be a tailcall.
        auto link_trace = check_argument_match(trace);
        if (link_trace) {
          if (verbose) {
            printf("Record stop up-recursion\n");
          }
          record_stop(pc, link_trace->num);
          return true;
        }
      }
    } else {
      if (cnt > UNROLL_ABORT_LIMIT) {
        // Flush trace.
        if ((patchpc == pc) && INS_OP(patchold) == JFUNC) {
          auto sl_trace = trace_cache_get(INS_D(patchold));
          if (sl_trace->link != INS_D(patchold)) {
            // printf("Flushing trace %i because it links to %i\n",
            // sl_trace->num, sl_trace->link);
            pendpatch();
            penalty_pc(pc);
            trace_flush(traces[INS_D(*pc)], false);
          }
        }
        hotmap[hotmap_hash(pc)] = 1;
        if (verbose) {
          printf("Record abort: unroll limit reached\n");
        }
        record_abort();
        return true;
      }
    }

    break;
  }
  case CALLCC: {
    // TODO(djwatson): this snap and flush only need things below the current
    // frame.
    stack_top = INS_A(i) + 1;
    add_snap(regs_list, regs - regs_list - 1, trace, pc, depth, stack_top);
    trace->snaps[arrlen(trace->snaps) - 1].exits = 255;
    push_ir(trace, IR_SAVEAP, 0, 0, UNDEFINED_TAG);
    auto op1 = push_ir(trace, IR_FLUSH, 0, 0, UNDEFINED_TAG);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (gc_obj){.ptr = vm_callcc});
    auto cont = push_ir(trace, IR_CALLXS, op1, knum | IR_CONST_BIAS, CONT_TAG);
    push_ir(trace, IR_RESAP, 0, 0, UNDEFINED_TAG);
    // TODO(djwatson) check GC result
    regs[INS_A(i)] = cont;
    knum = arrlen(trace->consts);
    arrput(trace->consts, FALSE_REP);
    push_ir(trace, IR_NE, cont, knum | IR_CONST_BIAS,
            UNDEFINED_TAG | IR_INS_TYPE_GUARD);
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);
    break;
  }
  case CALLCC_RESUME: {
    auto c = record_stack_load(INS_B(i), frame);
    auto result = record_stack_load(INS_C(i), frame);

    // Check that we're going to the same return point,
    // almost like RET1.
    {
      auto cont = to_cont(frame[INS_B(i)]);
      auto resume_pc = cont->v[to_fixnum(cont->len) - 1];
      auto len_ref = push_ir(trace, IR_REF, c, 8 - PTR_TAG, UNDEFINED_TAG);
      auto len = push_ir(trace, IR_LOAD, len_ref, 0, FIXNUM_TAG);
      auto knum = arrlen(trace->consts);
      arrput(trace->consts, tag_fixnum(1));
      auto idx = push_ir(trace, IR_SUB, len, knum | IR_CONST_BIAS, FIXNUM_TAG);
      auto vref = push_ir(trace, IR_VREF, c, idx, 0);
      auto dest = push_ir(trace, IR_LOAD, vref, 0, UNDEFINED_TAG);
      knum = arrlen(trace->consts);
      arrput(trace->consts, resume_pc);
      push_ir(trace, IR_EQ, dest, knum | IR_CONST_BIAS, UNDEFINED_TAG);
    }
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (gc_obj){.ptr = vm_cc_resume});
    push_ir(trace, IR_CCRES, c, knum | IR_CONST_BIAS, UNDEFINED_TAG);

    // TODO(djwatson): If the callcc exists in the same trace,
    //       we could optimize here and just pop depth/regs
    //       to the right place also.  I.e. callcc is just
    //       being used as a non-local return, and it's still
    //       on the stack.

    auto cont = to_cont(frame[INS_B(i)]);
    auto old_pc = to_return_address(cont->v[to_fixnum(cont->len) - 1]);
    auto frame_off = INS_A(*(old_pc - 1));
    stack_top = frame_off + 1;

    // TODO(djwatson) maybe also check for downrec?  Same as RET
    depth = 0;
    // add_snap(regs_list, regs - regs_list - 1, trace, pc, depth, -1);
    //  We must clear all of regs, because CC_resume smashes all of the stack.
    memset(regs_list, 0xff, sizeof(regs_list));
    regs = &regs_list[1];
    regs[frame_off] = result;
    knum = arrlen(trace->consts);
    arrput(trace->consts, (gc_obj){.ptr = old_pc});
    auto knum2 = arrlen(trace->consts);
    arrput(trace->consts, tag_fixnum(frame_off + 1));
    // We have to guard the return point *before* the CCRES call, so we don't
    // need to do it here also.
    push_ir(trace, IR_RET, knum | IR_CONST_BIAS, knum2 | IR_CONST_BIAS,
            CLOSURE_TAG);
    break;
  }
  case IRET1:
  case RET1: {
    if (depth == 0) {
      auto old_pc = to_return_address(frame[-1]);
      if (INS_OP(*pc_start) == RET1 || side_exit != nullptr) {
        int cnt = 0;
        for (uint64_t p = 0; p < arrlen(downrec); p++) {
          if (downrec[p] == pc) {
            cnt++;
          }
        }
        if (cnt != 0) {
          if (side_exit != nullptr && INS_OP(i) != IRET1) {
            if (verbose) {
              printf("Record abort: Potential down-recursion, restarting\n");
            }
            record_abort();
            record_start(pc, frame, 1);
            record_instr(pc, frame, 0);
            trace_state = TRACING;
            break;
          }
          if (pc == pc_start && !side_exit) {
            if (verbose) {
              printf("Record stop downrec\n");
            }
            record_stop(pc, arrlen(traces));
          } else {
            if (verbose) {
              printf("Record abort downrec\n");
            }
            record_abort();
          }
          return true;
        }
        arrput(downrec, pc);

        auto result = record_stack_load(INS_A(i), frame);
        // Guard down func type
        /* add_snap(regs_list, regs - regs_list - 1, trace, pc, depth,
         * INS_A(i)); */

        auto frame_off = INS_A(*(old_pc - 1));
        // printf("Continue down recursion, frame offset %i\n", frame_off);

        regs[frame_off] = result;
        // Clear space for the new (unknown) frame stack variables.
        memset(regs, 0xff, frame_off * sizeof(regs[0]));

        auto knum = arrlen(trace->consts);
        arrput(trace->consts, (gc_obj){.raddress = old_pc});
        auto knum2 = arrlen(trace->consts);
        arrput(trace->consts, tag_fixnum(frame_off + 1));
        push_ir(trace, IR_RET, knum | IR_CONST_BIAS, knum2 | IR_CONST_BIAS,
                IR_INS_TYPE_GUARD | 0x5);

        stack_top = frame_off + 1;
        add_snap(regs_list, regs - regs_list - 1, trace,
                 to_return_address(frame[-1]), depth, stack_top);
      } else {
        if (INS_OP(trace->startpc) == LOOP && parent == nullptr) {
          auto penalty = find_penalty_pc(pc_start);
          if (penalty < BLACKLIST_MAX / 2) {
            if (verbose) {
              printf("Record abort: Loop root trace exited loop\n");
            }
            record_abort();
          } else {
            if (verbose) {
              printf("Record stop return\n");
            }
            record_stop(pc, -1);
          }
        } else {
          if (verbose) {
            printf("Record abort: return\n");
          }
          record_abort();
        }
        return true;
      }
    } else if (depth > 0) {
      depth--;
      regs[-1] = regs[INS_A(i)];
      auto old_pc = to_return_address(frame[-1]);
      stack_top = INS_A(*(old_pc - 1)) + 1;
      assert(regs >= regs_list);
      regs -= (INS_A(*(old_pc - 1)) + 1);
      assert(regs >= regs_list);
    } else {
      depth--;
      printf("TODO return below trace\n");
      exit(-1);
    }
    break;
  }
  case LCALL:
  case CALL: {
    for (int j = INS_A(i) + 1; j < INS_A(i) + INS_B(i); j++) {
      regs[j] = record_stack_load(j, frame);
    }
    if (INS_OP(i) == CALL) {
      auto clo = record_stack_load(INS_A(i) + 1, frame);
      if (!ir_is_const(clo)) {
        /* add_snap(regs_list, regs - regs_list - 1, trace, pc, depth,
         * INS_A(i) + INS_B(i)); */
        auto ref = push_ir(trace, IR_REF, clo, 16 - CLOSURE_TAG, UNDEFINED_TAG);
        auto fun = push_ir(trace, IR_LOAD, ref, 0, 0);
        regs[INS_A(i)] = fun;
        auto cl = frame[INS_A(i) + 1];
        auto closure = to_closure(cl);
        auto knum = arrlen(trace->consts);
        arrput(trace->consts, closure->v[0]);
        push_ir(trace, IR_EQ, fun, knum | IR_CONST_BIAS, IR_INS_TYPE_GUARD);
      }
    }
    // Otherwise it's a label call, we must always go to this label.

    // Check call type
    /*
    {
      auto v = frame[INS_A(i) + 1];
      auto knum = arrlen(trace->consts);
      arrput(trace->consts, v);
      ir_ins ins;
      ins.reg = REG_NONE;
      ins.op1 = record_stack_load(INS_A(i) + 1, frame);
      ins.op2 = knum | IR_CONST_BIAS;
      ins.op = IR_EQ;
      // TODO(djwatson) magic number
      ins.type = IR_INS_TYPE_GUARD | 0x5;
      arrput(trace->ops, ins);
    }
    */

    // Setup frame
    depth++;
    // Push PC link as const
    {
      auto knum = arrlen(trace->consts);
      arrput(trace->consts, ((gc_obj){.raddress = pc + 1}));
      regs[INS_A(i)] = knum | IR_CONST_BIAS; // TODO(djwatson) set PC
    }

    // Increment regs
    assert(regs >= regs_list);
    regs += INS_A(i) + 1;
    assert(regs >= regs_list);

    stack_top = INS_A(i) + INS_B(i);

    break;
  }
  case LCALLT:
  case CALLT: {
    if (INS_OP(i) == CALLT) {
      // Record the tailcall for checking for loop endings.
      {
        auto clo = to_closure(frame[INS_A(i) + 1]);
        auto call_pc = &closure_code_ptr(clo)->code[0];
        auto v = hmget(tailcalled, call_pc);
        hmput(tailcalled, call_pc, v + 1);
      }
      // Check call type
      {
        auto clo = record_stack_load(INS_A(i) + 1, frame);
        if (!ir_is_const(clo)) {
          /* add_snap(regs_list, regs - regs_list - 1, trace, pc, depth,
           * INS_A(i) + INS_B(i)); */
          auto ref =
              push_ir(trace, IR_REF, clo, 16 - CLOSURE_TAG, UNDEFINED_TAG);
          auto fun = push_ir(trace, IR_LOAD, ref, 0, 0);
          regs[INS_A(i)] = fun;
          auto cl = frame[INS_A(i) + 1];
          auto closure = to_closure(cl);
          auto knum = arrlen(trace->consts);
          arrput(trace->consts, closure->v[0]);
          push_ir(trace, IR_EQ, fun, knum | IR_CONST_BIAS, IR_INS_TYPE_GUARD);
        }
      }
    } else {
      // Label call
      // Record the tailcall for checking for loop endings.
      {
        auto lfunc = to_func(frame[INS_A(i)]);
        auto call_pc = &lfunc->code[0];
        auto v = hmget(tailcalled, call_pc);
        hmput(tailcalled, call_pc, v + 1);
      }
    }
    /*
    {
      auto v = frame[INS_A(i) + 1];
      auto knum = arrlen(trace->consts);
      arrput(trace->consts, v);
      ir_ins ins;
      ins.reg = REG_NONE;
      ins.op1 = record_stack_load(INS_A(i) + 1, frame);
      ins.op2 = knum | IR_CONST_BIAS;
      ins.op = IR_EQ;
      // TODO(djwatson) magic number
      ins.type = IR_INS_TYPE_GUARD | 0x5;
      arrput(trace->ops, ins);
    }
    */
    // Move args down
    // TODO(djwatson) also check func
    for (int j = INS_A(i) + 1; j < INS_A(i) + INS_B(i); j++) {
      regs[j] = record_stack_load(j, frame);
    }
    memmove(&regs[0], &regs[INS_A(i) + 1], sizeof(int) * (INS_B(i) - 1));
    stack_top = INS_B(i);

    break;
  }
  case KSHORT: {
    // Lots of casting to avoid left-shifting a signed number.
    // Frontend has already verified the signed number fits in
    // int16_t, so shift is okay.
    int64_t k = (uint64_t)((int64_t)(int16_t)INS_D(i)) << 3; // NOLINT
    auto reg = INS_A(i);
    regs[reg] = arrlen(trace->consts) | IR_CONST_BIAS;
    arrput(trace->consts, (gc_obj){.value = k});
    stack_top = INS_A(i) + 1;
    break;
  }
  case STRING_SYMBOL: {
    // TODO(djwatson) snapshots
    auto op1 = record_stack_load(INS_B(i), frame);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (gc_obj){.ptr = vm_string_symbol});
    push_ir(trace, IR_SAVEAP, 0, 0, UNDEFINED_TAG);
    auto sym = push_ir(trace, IR_CALLXS, op1, knum | IR_CONST_BIAS, SYMBOL_TAG);
    push_ir(trace, IR_RESAP, 0, 0, UNDEFINED_TAG);
    regs[INS_A(i)] = sym;
    knum = arrlen(trace->consts);
    arrput(trace->consts, FALSE_REP);
    push_ir(trace, IR_NE, sym, knum | IR_CONST_BIAS,
            UNDEFINED_TAG | IR_INS_TYPE_GUARD);
    stack_top = INS_A(i) + 1;
    break;
  }
  case SYMBOL_STRING: {
    auto op1 = record_stack_load(INS_B(i), frame);
    auto ref = push_ir(trace, IR_REF, op1, 8 - SYMBOL_TAG, UNDEFINED_TAG);
    regs[INS_A(i)] = push_ir(trace, IR_LOAD, ref, 0, STRING_TAG);
    stack_top = INS_A(i) + 1;
    break;
  }
  case CHAR_INTEGER: {
    auto op1 = record_stack_load(INS_B(i), frame);
    regs[INS_A(i)] = push_ir(trace, IR_SHR, op1, 5, FIXNUM_TAG);
    stack_top = INS_A(i) + 1;
    break;
  }
  case INTEGER_CHAR: {
    auto op1 = record_stack_load(INS_B(i), frame);
    if (get_object_ir_type(frame[INS_B(i)]) != FIXNUM_TAG) {
      printf("Record abort: integer->char with non-char");
      record_abort();
      return true;
    }
    regs[INS_A(i)] = push_ir(trace, IR_CHGTYPE, op1, FIXNUM_TAG, CHAR_TAG);
    stack_top = INS_A(i) + 1;
    break;
  }
  case JISF: {
    record_jcomp1(JISF, IR_NE, IR_EQ, INS_B(i), INS_B(i), frame, pc);
    break;
  }
  case JIST: {
    record_jcomp1(JIST, IR_EQ, IR_NE, INS_B(i), INS_B(i), frame, pc);
    break;
  }
  case JISLT: {
    return record_jcomp2(JISLT, IR_LT, IR_GE, INS_B(i), INS_C(i), frame, pc,
                         true);
  }
  case JISGT: {
    return record_jcomp2(JISGT, IR_GT, IR_LE, INS_B(i), INS_C(i), frame, pc,
                         true);
  }
  case JISGTE: {
    return record_jcomp2(JISGTE, IR_GE, IR_LT, INS_B(i), INS_C(i), frame, pc,
                         true);
  }
  case JISLTE: {
    return record_jcomp2(JISLTE, IR_LE, IR_GT, INS_B(i), INS_C(i), frame, pc,
                         true);
  }
  case JEQV:
  case JEQ:
  case JISEQ: {
    if (INS_OP(i) == JEQV &&
        (is_flonum(frame[INS_B(i)]) || is_flonum(frame[INS_C(i)]))) {
      if (verbose) {
        printf("Record abort: flonum not supported in jeqv\n");
      }
      record_abort();
      return true;
    }
    return record_jcomp2(JEQ, IR_EQ, IR_NE, INS_B(i), INS_C(i), frame, pc,
                         false);
  }
  case JNEQ:
  case JNEQV:
  case JISNEQ: {
    if (INS_OP(i) == JNEQV &&
        (is_flonum(frame[INS_B(i)]) || is_flonum(frame[INS_C(i)]))) {
      if (verbose) {
        printf("Record abort: flonum not supported in jneqv\n");
      }
      record_abort();
      return true;
    }
    return record_jcomp2(JNEQ, IR_NE, IR_EQ, INS_B(i), INS_C(i), frame, pc,
                         false);
  }
  case SET_CDR:
  case SET_CAR: {
    auto box = record_stack_load(INS_A(i), frame);
    auto obj = record_stack_load(INS_B(i), frame);
    uint32_t offset = 0;
    if (INS_OP(i) == SET_CDR) {
      offset = 8;
    }
    push_ir(trace, IR_GCLOG, box, IR_NONE, CONS_TAG);
    auto ref = push_ir(trace, IR_REF, box, 8 + offset - CONS_TAG, 0);
    push_ir(trace, IR_STORE, ref, obj, UNDEFINED_TAG);
    // Modified state, need a snap.
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);
    // No stack top tracking
    break;
  }
  case SET_BOX: {
    auto box = record_stack_load(INS_B(i), frame);
    auto obj = record_stack_load(INS_C(i), frame);
    push_ir(trace, IR_GCLOG, box, IR_NONE, CONS_TAG);
    auto ref = push_ir(trace, IR_REF, box, 8 - CONS_TAG, 0);
    push_ir(trace, IR_STORE, ref, obj, UNDEFINED_TAG);
    // Modified state, need a snap.
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);
    // No stack top tracking
    break;
  }
  case UNBOX: // DO don't need typecheck
  case CDR:
  case CAR: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t offset = 0;
    uint8_t type;
    gc_obj obj;
    if (ir_is_const(op1)) {
      obj = trace->consts[op1 - IR_CONST_BIAS];
    } else {
      obj = frame[INS_B(i)];
    }
    if (!is_cons(obj)) {
      printf("Record abort: car/cdr/unbox of non-cons cell\n");
      record_abort();
      return true;
    }
    if (INS_OP(i) == CAR || INS_OP(i) == UNBOX) {
      // TODO(djwatson) typecheck
      // TODO(djwatson) cleanup
      type = get_object_ir_type(to_cons(obj)->a);
    } else {
      type = get_object_ir_type(to_cons(obj)->b);
      offset = sizeof(gc_obj);
    }
    auto ref =
        push_ir(trace, IR_REF, op1, 8 - CONS_TAG + offset, UNDEFINED_TAG);
    regs[INS_A(i)] =
        push_ir(trace, IR_LOAD, ref, IR_NONE, type | IR_INS_TYPE_GUARD);
    stack_top = INS_A(i) + 1;
    break;
  }
  case ISEQ:
  case EQV:
  case EQ: {
    return record_comp2(EQ, IR_EQ, IR_NE, INS_A(i), INS_B(i), INS_C(i), frame);
  }
  case ISLTE: {
    return record_comp2(ISLTE, IR_LE, IR_GT, INS_A(i), INS_B(i), INS_C(i),
                        frame);
  }
  case ISLT: {
    return record_comp2(ISLT, IR_LT, IR_GE, INS_A(i), INS_B(i), INS_C(i),
                        frame);
  }
  case ISGT: {
    return record_comp2(ISGT, IR_GT, IR_LE, INS_A(i), INS_B(i), INS_C(i),
                        frame);
  }
  case ISGTE: {
    return record_comp2(ISGTE, IR_GE, IR_LT, INS_A(i), INS_B(i), INS_C(i),
                        frame);
  }
  case GUARD: {
    record_stack_load(INS_B(i), frame);
    auto v = frame[INS_B(i)];
    auto type = INS_C(i);
    auto c = FALSE_REP;
    auto obj_type = get_object_ir_type(v);
    if (obj_type == type) {
      c = TRUE_REP;
    }
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, c);
    regs[INS_A(i)] = IR_CONST_BIAS + knum;
    stack_top = INS_A(i) + 1;
    break;
  }
  case JNGUARD:
  case JGUARD: {
    record_stack_load(INS_B(i), frame);
    uint8_t type = get_object_ir_type(frame[INS_B(i)]);
    stack_top = INS_A(i);
    bool result = (type == INS_C(i));
    if (INS_OP(i) == JNGUARD) {
      result = !result;
    }
    if (result) {
      add_snap(regs_list, regs - regs_list - 1, trace, pc + 2, depth,
               stack_top);
    } else {
      add_snap(regs_list, regs - regs_list - 1, trace,
               pc + 1 + INS_D(*(pc + 1)), depth, stack_top);
    }
    break;
  }
  case KONST: {
    auto k = const_table[INS_D(i)];
    auto reg = INS_A(i);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, k);
    regs[reg] = IR_CONST_BIAS + knum;
    stack_top = INS_A(i) + 1;
    break;
  }
  case KFUNC: {
    auto k = tag_func(funcs[INS_D(i)]);
    auto reg = INS_A(i);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, k);
    regs[reg] = IR_CONST_BIAS + knum;
    stack_top = INS_A(i) + 1;
    break;
  }
  case VECTOR_SET: {
    auto vec = record_stack_load(INS_A(i), frame);
    auto idx = record_stack_load(INS_B(i), frame);
    auto obj = record_stack_load(INS_C(i), frame);

    push_ir(trace, IR_GCLOG, vec, IR_NONE, UNDEFINED_TAG);
    push_ir(trace, IR_ABC, vec, idx, IR_INS_TYPE_GUARD | VECTOR_TAG);
    auto vref = push_ir(trace, IR_VREF, vec, idx, 0);
    push_ir(trace, IR_STORE, vref, obj, 0);

    // Record state because of IR_STORE
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);
    // No stack top tracking
    break;
  }
  case VECTOR_REF: {
    auto vec = record_stack_load(INS_B(i), frame);
    auto idx = record_stack_load(INS_C(i), frame);

    push_ir(trace, IR_ABC, vec, idx, IR_INS_TYPE_GUARD | VECTOR_TAG);
    auto vref = push_ir(trace, IR_VREF, vec, idx, 0);

    uint64_t pos = to_fixnum(frame[INS_C(i)]);
    vector_s *vec_d = to_vector(frame[INS_B(i)]);
    uint8_t type = get_object_ir_type(vec_d->v[pos]);
    regs[INS_A(i)] = push_ir(trace, IR_LOAD, vref, 0, IR_INS_TYPE_GUARD | type);
    stack_top = INS_A(i) + 1;

    break;
  }
  case STRING_REF: {
    auto str = record_stack_load(INS_B(i), frame);
    auto idx = record_stack_load(INS_C(i), frame);

    push_ir(trace, IR_ABC, str, idx, IR_INS_TYPE_GUARD | STRING_TAG);
    regs[INS_A(i)] = push_ir(trace, IR_STRLD, str, idx, CHAR_TAG);
    stack_top = INS_A(i) + 1;

    break;
  }
  case STRING_SET: {
    auto str = record_stack_load(INS_A(i), frame);
    auto idx = record_stack_load(INS_B(i), frame);
    auto val = record_stack_load(INS_C(i), frame);

    push_ir(trace, IR_ABC, str, idx, IR_INS_TYPE_GUARD | STRING_TAG);
    auto ref = push_ir(trace, IR_STRREF, str, idx, 0);
    push_ir(trace, IR_STRST, ref, val, 0);
    stack_top = INS_A(i) + 1;

    break;
  }
  case CLOSURE: {
    // Check for monomorphic -> polymorphic
    {
      auto bfunc = to_func(frame[INS_A(i)]);
      if (bfunc->poly_cnt < 2) {
        if (verbose) {
          printf("Record abort: non-polymorphic closure\n");
        }
        record_abort();
        return -1;
      }
    }
    add_snap(regs_list, regs - regs_list - 1, trace, pc, depth,
             INS_A(i) + INS_B(i));
    // TODO(djwatson) this forces a side exit without recording.
    // Put GC inline in generated code?  Would have to flush
    // all registers to stack.
    trace->snaps[arrlen(trace->snaps) - 1].exits = 255;
    // TODO(djwatson) fixed closz
    auto closz = INS_B(i);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts,
           tag_fixnum(sizeof(gc_obj) * closz + sizeof(closure_s)));
    auto cell = push_ir(trace, IR_ALLOC, knum | IR_CONST_BIAS, CLOSURE_TAG,
                        CLOSURE_TAG);
    auto ref = push_ir(trace, IR_REF, cell, 8 - CLOSURE_TAG, UNDEFINED_TAG);
    knum = arrlen(trace->consts);
    arrput(trace->consts, tag_fixnum(closz));
    push_ir(trace, IR_STORE, ref, knum | IR_CONST_BIAS, 0);
    auto cnt = INS_B(i);
    for (uint8_t j = 0; j < cnt; j++) {
      record_stack_load(INS_A(i) + j, frame);
    }
    for (uint8_t j = 0; j < closz; j++) {
      // Already loaded above
      auto a = record_stack_load(INS_A(i) + j, frame);
      ref =
          push_ir(trace, IR_REF, cell, 16 + 8 * j - CLOSURE_TAG, UNDEFINED_TAG);
      push_ir(trace, IR_STORE, ref, a, 0);
    }
    regs[INS_A(i)] = cell;
    stack_top = INS_A(i) + 1;
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);
    break;
  }
  case BOX:
  case CONS: {
    auto a = record_stack_load(INS_B(i), frame);
    int64_t b;
    if (INS_OP(i) == CONS) {
      b = record_stack_load(INS_C(i), frame);
    } else {
      // BOX
      auto knum = arrlen(trace->consts);
      arrput(trace->consts, NIL);
      b = knum | IR_CONST_BIAS;
    }
    add_snap(regs_list, regs - regs_list - 1, trace, pc, depth,
             max_slot3(i) + 1);
    // TODO(djwatson) this forces a side exit without recording.
    // Put GC inline in generated code?  Would have to flush
    // all registers to stack.
    trace->snaps[arrlen(trace->snaps) - 1].exits = 255;
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_fixnum(sizeof(cons_s)));
    auto cell =
        push_ir(trace, IR_ALLOC, knum | IR_CONST_BIAS, CONS_TAG, CONS_TAG);
    regs[INS_A(i)] = cell;
    auto ref = push_ir(trace, IR_REF, cell, 8 - CONS_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, a, UNDEFINED_TAG);
    ref = push_ir(trace, IR_REF, cell, 8 + 8 - CONS_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, b, UNDEFINED_TAG);
    stack_top = INS_A(i) + 1;
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);

    break;
  }
  case MAKE_STRING: {
    auto sz = record_stack_load(INS_B(i), frame);
    auto ch = record_stack_load(INS_C(i), frame);

    add_snap(regs_list, regs - regs_list - 1, trace, pc, depth,
             max_slot3(i) + 1);
    // TODO(djwatson) this forces a side exit without recording.
    // Put GC inline in generated code?  Would have to flush
    // all registers to stack.
    trace->snaps[arrlen(trace->snaps) - 1].exits = 255;

    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_fixnum(sizeof(string_s) + 1 + 7 /* ptr align */));
    auto alloc_sz =
        push_ir(trace, IR_ADD, sz, knum | IR_CONST_BIAS, FIXNUM_TAG);
    knum = arrlen(trace->consts);
    arrput(trace->consts, tag_fixnum(~TAG_MASK));
    auto alloc_sz_aligned =
        push_ir(trace, IR_AND, alloc_sz, knum | IR_CONST_BIAS, FIXNUM_TAG);
    // TODO(djwatson) snaps??
    auto cell = push_ir(trace, IR_ALLOC, alloc_sz_aligned, PTR_TAG, STRING_TAG);

    auto ref = push_ir(trace, IR_REF, cell, 8 - PTR_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, sz, UNDEFINED_TAG);
    regs[INS_A(i)] = cell;

    // Set the string values to ch
    // Basically using memset, because that's what gcc/clang would do.
    // TODO(djwatson) could optimize away if sz = 0 or ch isn't passed (i.e.
    // (make-string 100))
    auto arg = push_ir(trace, IR_CARG, cell, ch, UNDEFINED_TAG);
    knum = arrlen(trace->consts);
    arrput(trace->consts, tag_ptr(vm_make_string));
    push_ir(trace, IR_CALLXS, arg, knum | IR_CONST_BIAS, UNDEFINED_TAG);
    stack_top = INS_A(i) + 1;
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);

    break;
  }
  case MAKE_VECTOR: {
    auto sz = record_stack_load(INS_B(i), frame);
    auto ch = record_stack_load(INS_C(i), frame);

    add_snap(regs_list, regs - regs_list - 1, trace, pc, depth,
             max_slot3(i) + 1);
    // TODO(djwatson) this forces a side exit without recording.
    // Put GC inline in generated code?  Would have to flush
    // all registers to stack.
    trace->snaps[arrlen(trace->snaps) - 1].exits = 255;

    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_fixnum(2));
    auto alloc_sz =
        push_ir(trace, IR_ADD, sz, knum | IR_CONST_BIAS, FIXNUM_TAG);
    knum = arrlen(trace->consts);
    arrput(trace->consts, tag_fixnum(8));
    auto alloc_sz_aligned =
        push_ir(trace, IR_MUL, alloc_sz, knum | IR_CONST_BIAS, FIXNUM_TAG);
    // TODO(djwatson) snaps??
    auto cell =
        push_ir(trace, IR_ALLOC, alloc_sz_aligned, VECTOR_TAG, VECTOR_TAG);

    auto ref = push_ir(trace, IR_REF, cell, 8 - VECTOR_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, sz, UNDEFINED_TAG);
    regs[INS_A(i)] = cell;

    auto arg = push_ir(trace, IR_CARG, cell, ch, UNDEFINED_TAG);
    knum = arrlen(trace->consts);
    arrput(trace->consts, tag_ptr(vm_make_vector));
    push_ir(trace, IR_CALLXS, arg, knum | IR_CONST_BIAS, UNDEFINED_TAG);
    stack_top = INS_A(i) + 1;
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);

    break;
  }
  case VECTOR: {
    auto len = INS_B(i);
    auto reg = INS_A(i);
    int *loaded = NULL;
    for (uint32_t cnt = 0; cnt < len; cnt++) {
      arrput(loaded, record_stack_load(reg + cnt, frame));
    }
    add_snap(regs_list, regs - regs_list - 1, trace, pc, depth, reg + len);
    // TODO(djwatson) this forces a side exit without recording.
    // Put GC inline in generated code?  Would have to flush
    // all registers to stack.
    trace->snaps[arrlen(trace->snaps) - 1].exits = 255;

    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_fixnum(sizeof(vector_s) + 8UL * len));
    auto cell =
        push_ir(trace, IR_ALLOC, knum | IR_CONST_BIAS, VECTOR_TAG, VECTOR_TAG);
    regs[reg] = cell;
    auto ref = push_ir(trace, IR_REF, cell, 8 - VECTOR_TAG, UNDEFINED_TAG);
    knum = arrlen(trace->consts);
    arrput(trace->consts, tag_fixnum(len));
    push_ir(trace, IR_STORE, ref, knum | IR_CONST_BIAS, UNDEFINED_TAG);
    for (uint32_t cnt = 0; cnt < len; cnt++) {
      ref = push_ir(trace, IR_REF, cell, 16 + cnt * 8 - VECTOR_TAG,
                    UNDEFINED_TAG);
      push_ir(trace, IR_STORE, ref, loaded[cnt], UNDEFINED_TAG);
    }
    stack_top = INS_A(i) + 1;
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);
    arrfree(loaded);

    break;
  }
  case MOV: {
    regs[INS_A(i)] = record_stack_load(INS_B(i), frame);
    // No stack top tracking
    break;
  }
  case STRING_COPY: {
    auto slot = INS_A(i);
    auto arg4 = push_ir(trace, IR_CARG, record_stack_load(slot + 3, frame),
                        record_stack_load(slot + 4, frame), UNDEFINED_TAG);
    auto arg3 = push_ir(trace, IR_CARG, record_stack_load(slot + 2, frame),
                        arg4, UNDEFINED_TAG);
    auto arg2 = push_ir(trace, IR_CARG, record_stack_load(slot + 1, frame),
                        arg3, UNDEFINED_TAG);
    auto arg1 = push_ir(trace, IR_CARG, record_stack_load(slot, frame), arg2,
                        UNDEFINED_TAG);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_ptr(vm_string_copy));
    push_ir(trace, IR_CALLXS, arg1, knum | IR_CONST_BIAS, UNDEFINED_TAG);
    stack_top = INS_A(i);
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);
    break;
  }
  case PEEK:
  case READ: {
    port_s *port = to_port(frame[INS_B(i)]);
    uint8_t type = CHAR_TAG;
    // TODO(djwatson) peek instead.
    if (port->eof.value == TRUE_REP.value) {
      type = EOF_TAG;
    }
    uint8_t op = IR_READCH;
    if (INS_OP(i) == PEEK) {
      op = IR_PEEKCH;
    }
    regs[INS_A(i)] = push_ir(trace, op, record_stack_load(INS_B(i), frame),
                             IR_NONE, type | IR_INS_TYPE_GUARD);
    stack_top = INS_A(i) + 1; // TODO(djwatson) don't need +1?
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);
    break;
  }
  case WRITE: {
    auto arg = push_ir(trace, IR_CARG, record_stack_load(INS_B(i), frame),
                       record_stack_load(INS_C(i), frame), UNDEFINED_TAG);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_ptr(vm_write));
    push_ir(trace, IR_CALLXS, arg, knum | IR_CONST_BIAS, UNDEFINED_TAG);
    stack_top = INS_A(i) + 1;
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);
    break;
  }
  case EQUAL: {
    auto arg = push_ir(trace, IR_CARG, record_stack_load(INS_B(i), frame),
                       record_stack_load(INS_C(i), frame), UNDEFINED_TAG);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_ptr(equalp));
    regs[INS_A(i)] =
        push_ir(trace, IR_CALLXS, arg, knum | IR_CONST_BIAS, BOOL_TAG);
    stack_top = INS_A(i) + 1;
    break;
  }
  case LENGTH: {
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_ptr(vm_length));
    regs[INS_A(i)] =
        push_ir(trace, IR_CALLXS, record_stack_load(INS_B(i), frame),
                knum | IR_CONST_BIAS, FIXNUM_TAG);
    stack_top = INS_A(i) + 1;
    break;
  }
  case MEMQ: {
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_ptr(vm_memq));
    auto res = vm_memq(frame[INS_B(i)], frame[INS_C(i)]);
    auto typ = get_object_ir_type(res);
    auto arg = push_ir(trace, IR_CARG, record_stack_load(INS_B(i), frame),
                       record_stack_load(INS_C(i), frame), UNDEFINED_TAG);
    regs[INS_A(i)] = push_ir(trace, IR_CALLXS, arg, knum | IR_CONST_BIAS,
                             typ | IR_INS_TYPE_GUARD);
    stack_top = INS_A(i) + 1;
    break;
  }
  case ASSQ: {
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_ptr(vm_assq));
    auto res = vm_assq(frame[INS_B(i)], frame[INS_C(i)]);
    auto typ = get_object_ir_type(res);
    auto arg = push_ir(trace, IR_CARG, record_stack_load(INS_B(i), frame),
                       record_stack_load(INS_C(i), frame), UNDEFINED_TAG);
    regs[INS_A(i)] = push_ir(trace, IR_CALLXS, arg, knum | IR_CONST_BIAS,
                             typ | IR_INS_TYPE_GUARD);
    stack_top = INS_A(i) + 1;
    break;
  }
  case ASSV: {
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_ptr(vm_assv));
    auto res = vm_assq(frame[INS_B(i)], frame[INS_C(i)]);
    auto typ = get_object_ir_type(res);
    auto arg = push_ir(trace, IR_CARG, record_stack_load(INS_B(i), frame),
                       record_stack_load(INS_C(i), frame), UNDEFINED_TAG);
    regs[INS_A(i)] = push_ir(trace, IR_CALLXS, arg, knum | IR_CONST_BIAS,
                             typ | IR_INS_TYPE_GUARD);
    stack_top = INS_A(i) + 1;
    break;
  }
  case GGET: {
    // TODO(djwatson) check it is set?
    auto gp = const_table[INS_D(i)];
    symbol *g = to_symbol(gp);
    if (g->opt != -1 && is_closure(g->val)) {
      g->opt = 1;
      hmputs(g->lst, (struct tv){.key = trace->num});
      auto knum = arrlen(trace->consts);
      arrput(trace->consts, gp);
      arrput(trace->syms, knum);
      knum = arrlen(trace->consts);
      arrput(trace->consts, g->val);
      regs[INS_A(i)] = knum | IR_CONST_BIAS;
    } else {
      auto knum = arrlen(trace->consts);
      arrput(trace->consts, gp);
      symbol *sym = to_symbol(gp);
      uint8_t type = get_object_ir_type(sym->val);
      regs[INS_A(i)] = push_ir(trace, IR_GGET, knum | IR_CONST_BIAS, IR_NONE,
                               type | IR_INS_TYPE_GUARD);
    }
    stack_top = INS_A(i) + 1;
    break;
  }
  case GSET: {
    auto gp = const_table[INS_D(i)];
    symbol *g = to_symbol(gp);
    if (is_undefined(g->val) || (g->opt != 0 && g->opt != -1)) {
      if (verbose) {
        printf("Record abort: Setting a currently-const global %s %" PRId64
               "\n",
               get_sym_name(g)->str, g->opt);
      }
      record_abort();
      return true;
    }
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, gp);
    push_ir(trace, IR_GCLOG, knum | IR_CONST_BIAS, IR_NONE, SYMBOL_TAG);
    push_ir(trace, IR_GSET, knum | IR_CONST_BIAS,
            record_stack_load(INS_A(i), frame), UNDEFINED_TAG);
    // We've changed global state, add a snap.
    stack_top = INS_A(i) + 1;
    add_snap(regs_list, regs - regs_list - 1, trace, pc + 1, depth, stack_top);
    break;
  }
  case SUBVN: {
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_fixnum(((int64_t)((int8_t)INS_C(i)))));
    auto op1 = record_stack_load(INS_B(i), frame);
    uint8_t type = 0;
    if (op1 >= IR_CONST_BIAS) {
      type = get_tag(trace->consts[op1 - IR_CONST_BIAS]);
    } else {
      type = get_type(trace->ops[op1].type);
    }
    if (type != 0) {
      if (verbose) {
        printf("Record abort: Only int supported in trace: %i\n", type);
      }
      record_abort();
      return true;
    }
    regs[INS_A(i)] = push_ir(trace, IR_SUB, op1, knum | IR_CONST_BIAS,
                             IR_INS_TYPE_GUARD | type);
    stack_top = INS_A(i) + 1;
    break;
  }
  case ADDVN: {
    // TODO(djwatson) check type
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, tag_fixnum((int64_t)((int8_t)INS_C(i))));
    auto op1 = record_stack_load(INS_B(i), frame);
    uint8_t type = 0;
    if (op1 >= IR_CONST_BIAS) {
      type = get_tag(trace->consts[op1 - IR_CONST_BIAS]);
    } else {
      type = get_type(trace->ops[op1].type);
    }
    if (type != 0) {
      if (verbose) {
        printf("Record abort: Only int supported in trace: %i\n", type);
      }
      record_abort();
      return true;
    }
    regs[INS_A(i)] = push_ir(trace, IR_ADD, op1, knum | IR_CONST_BIAS,
                             type | IR_INS_TYPE_GUARD);
    stack_top = INS_A(i) + 1;
    break;
  }
  case ADDVV: {
    auto op1 = record_stack_load(INS_B(i), frame);
    auto op2 = record_stack_load(INS_C(i), frame);
    // TODO(djwatson): Assume no type change??
    uint8_t type = 0;
    if (op1 >= IR_CONST_BIAS) {
      type = get_tag(trace->consts[op1 - IR_CONST_BIAS]);
    } else {
      type = get_type(trace->ops[op1].type);
    }
    if (type != 0) {
      if (verbose) {
        printf("Record abort: Only int supported in trace: %i\n", type);
      }
      record_abort();
      return true;
    }
    regs[INS_A(i)] = push_ir(trace, IR_ADD, op1, op2, IR_INS_TYPE_GUARD | type);
    stack_top = INS_A(i) + 1;
    break;
  }
  case SUBVV: {
    auto op1 = record_stack_load(INS_B(i), frame);
    auto op2 = record_stack_load(INS_C(i), frame);
    // TODO(djwatson): Assume no type change??
    uint8_t type = 0;
    if (op1 >= IR_CONST_BIAS) {
      type = get_tag(trace->consts[op1 - IR_CONST_BIAS]);
    } else {
      type = get_type(trace->ops[op1].type);
    }
    if (type != 0) {
      if (verbose) {
        printf("Record abort: Only int supported in trace: %i\n", type);
      }
      record_abort();
      return true;
    }
    regs[INS_A(i)] = push_ir(trace, IR_SUB, op1, op2, IR_INS_TYPE_GUARD | type);
    stack_top = INS_A(i) + 1;
    break;
  }
  case MULVV:
  case REM:
  case DIV: {
    auto op1 = record_stack_load(INS_B(i), frame);
    auto op2 = record_stack_load(INS_C(i), frame);
    // TODO(djwatson): Assume no type change??
    uint8_t type = 0;
    if (get_object_ir_type(frame[INS_B(i)]) != 0 ||
        get_object_ir_type(frame[INS_C(i)]) != 0) {
      if (verbose) {
        printf("Record abort: Only int supported in trace: %i\n", type);
      }
      record_abort();
      return true;
    }
    uint8_t op = IR_DIV;
    if (INS_OP(i) == REM) {
      op = IR_REM;
    } else if (INS_OP(i) == MULVV) {
      op = IR_MUL;
    }
    regs[INS_A(i)] = push_ir(trace, op, op1, op2, type);
    stack_top = INS_A(i) + 1;
    break;
  }
  case EXACT: {
    regs[INS_A(i)] = record_stack_load(INS_B(i), frame);
    auto type = get_object_ir_type(frame[INS_B(i)]);
    if (type != 0) {
      if (verbose) {
        printf("Record abort: exact only supports fixnum\n");
      }
      record_abort();
      return true;
    }
    stack_top = INS_A(i) + 1;
    break;
  }
  case STRING_LENGTH: {
    auto vec = record_stack_load(INS_B(i), frame);
    auto ref = push_ir(trace, IR_REF, vec, 8 - PTR_TAG, UNDEFINED_TAG);
    regs[INS_A(i)] = push_ir(trace, IR_LOAD, ref, 0, FIXNUM_TAG);
    stack_top = INS_A(i) + 1;
    break;
  }
  case VECTOR_LENGTH: {
    auto vec = record_stack_load(INS_B(i), frame);
    auto ref = push_ir(trace, IR_REF, vec, 8 - VECTOR_TAG, UNDEFINED_TAG);
    regs[INS_A(i)] = push_ir(trace, IR_LOAD, ref, 0, FIXNUM_TAG);
    stack_top = INS_A(i) + 1;
    break;
  }
  case CLOSURE_GET: {
    auto clo = record_stack_load(INS_B(i), frame);
    {
      auto closure = to_closure(frame[INS_B(i)]);
      auto bfun = closure_code_ptr(closure);
      if (bfun->poly_cnt <= 1 && to_fixnum(closure->len) != 1) {
        arrput(trace->func_opts, bfun);
        hmputs(bfun->lst, (struct tv){.key = trace->num});

        auto knum = arrlen(trace->consts);
        arrput(trace->consts, closure->v[1 + INS_C(i)]);
        regs[INS_A(i)] = knum | IR_CONST_BIAS;
        break;
      }
    }
    auto ref = push_ir(trace, IR_REF, clo,
                       16 + (8 * (1 + INS_C(i))) - CLOSURE_TAG, UNDEFINED_TAG);

    // Note: Closure doesn't necessarily need typecheck since closures are
    // CONST. However, there are some situations where invalid code may hit bad
    // types? I.e. polymorphic functions could do a different STORE type?
    //
    // Actually, this is invalid: closures could close '() or a list, and still
    // be what code is expecting.
    uint64_t pos = INS_C(i) + 1;
    closure_s *clo_d = to_closure(frame[INS_B(i)]);
    uint8_t type = get_object_ir_type(clo_d->v[pos]);

    regs[INS_A(i)] = push_ir(trace, IR_LOAD, ref, 0, IR_INS_TYPE_GUARD | type);
    stack_top = INS_A(i) + 1;

    // TODO(djwatson): closure may not be const
    /*
       auto fb = frame[INS_B(i)];
       auto closure = (closure_s *)(fb - CLOSURE_TAG);

       auto knum = (int)arrlen(trace->consts);
       arrput(trace->consts, closure->v[1 + INS_C(i)]);
       regs[INS_A(i)] = knum | IR_CONST_BIAS; */
    break;
  }
  case CLOSURE_SET: {
    auto clo = record_stack_load(INS_A(i), frame);
    auto val = record_stack_load(INS_B(i), frame);
    push_ir(trace, IR_GCLOG, clo, IR_NONE, CLOSURE_TAG);
    auto ref = push_ir(trace, IR_REF, clo,
                       16 + (8 * (1 + INS_C(i))) - CLOSURE_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, val, UNDEFINED_TAG);
    // No stack top tracking
    break;
  }
  case JMP: {
    // TODO(djwatson) track stack top?
    break;
  }
  case JFUNC: {
    // Check if it is a returning trace
    auto ctrace = trace_cache_get(INS_D(i));
    stack_top = INS_A(ctrace->startpc);
    if ((INS_OP(ctrace->startpc) == CLFUNC ||
         INS_OP(ctrace->startpc) == ICLFUNC) &&
        argcnt != INS_A(ctrace->startpc)) {
      // The check will fail, and we will fall through to a later
      // CLFUNC.
      break;
    }
    if ((INS_OP(ctrace->startpc) == CLFUNCV ||
         INS_OP(ctrace->startpc) == ICLFUNCV) &&
        argcnt < INS_A(ctrace->startpc)) {
      // The check will fail, and we will fall through to a later
      // CLFUNC.
      break;
    }
    // Check if our argument types match.  If not, we trace through.
    // If it is a returning non-looping trace, trace through it.
    if (ctrace->link == -1) {
      assert(patchpc == nullptr);
      patchpc = pc;
      patchold = *pc;
      *pc = traces[INS_D(*pc)]->startpc;
      return record_instr(pc, frame, argcnt);
    }
    // Otherwise, we're going to link to the JFUNC.
    for (int j = 0; j < INS_A(i); j++) {
      regs[j] = record_stack_load(j, frame);
    }
    auto link_trace = check_argument_match(traces[INS_D(*pc)]);
    if (!link_trace) {
      patchpc = pc;
      patchold = *pc;
      *pc = traces[INS_D(*pc)]->startpc;
      // Check if it is a FUNCV and emit a list build if necessary.
      return record_instr(pc, frame, argcnt);
    }

    if (verbose) {
      printf("Record stop JFUNC %s\n", ins_names[INS_OP(link_trace->startpc)]);
    }
    check_emit_funcv(link_trace->startpc, pc, frame, argcnt);
    record_stop(pc, link_trace->num);
    // No stack top tracking
    return true;
  }
  case JLOOP: {
    auto ctrace = trace_cache_get(INS_D(i));
    stack_top = INS_A(ctrace->startpc) + INS_B(ctrace->startpc);
    if (side_exit == nullptr && INS_OP(ctrace->startpc) != RET1) {
      auto penalty = find_penalty_pc(pc_start);
      if (penalty < BLACKLIST_MAX / 2) {
        if (verbose) {
          printf("Record abort: root trace hit jloop\n");
        }
        record_abort();
        return true;
      }
    }
    auto startpc = traces[INS_D(i)]->startpc;
    if (INS_OP(startpc) == RET1) {
      stack_top = INS_A(startpc) + 1;
    }
    trace_s *link_trace = traces[INS_D(i)];
    if (INS_OP(startpc) == LOOP || INS_OP(startpc) == ILOOP) {
      // Since some args are in registers for the loop, make sure they're loaded
      // here.
      for (int32_t arg = INS_A(startpc); arg < INS_A(startpc) + INS_B(startpc);
           arg++) {
        if (arg - INS_A(startpc) >= 6) {
          // TODO(djwatson) clean this up in the register allocator.
          break;
        }
        regs[arg] = record_stack_load(arg, frame);
      }
      link_trace = check_argument_match(traces[INS_D(i)]);
      if (!link_trace) {
        patchpc = pc;
        patchold = *pc;
        *pc = traces[INS_D(*pc)]->startpc;
        return record_instr(pc, frame, argcnt);
      }
    }
    // NOTE: stack load is for ret1 jloop returns.  Necessary?
    // TODO(djwatson) JLOOp also used for loop, only need to record for RET
    regs[INS_A(i)] = record_stack_load(INS_A(i), frame);
    if (verbose) {
      printf("Record stop hit JLOOP\n");
    }

    record_stop(pc, link_trace->num);
    return true;
  }
  default: {
    if (verbose) {
      bcfunc *fc = find_func_for_frame(pc);
      printf("Record abort: NYI: CANT RECORD BYTECODE %s in %s\n",
             ins_names[INS_OP(i)], fc ? fc->name : "???");
    }
    record_abort();
    return true;
    // exit(-1);
  }
  }
  return false;
}

trace_s *trace_cache_get(uint16_t tnum) {
  assert(tnum < arrlen(traces));
  return traces[tnum];
}

EXPORT void free_trace() {
  if (verbose && arrlen(traces)) {
    printf("Traces: %li\n", arrlen(traces));
  }
  for (uint64_t i = 0; i < arrlen(traces); i++) {
    for (uint64_t j = 0; j < arrlen(traces[i]->snaps); j++) {
      free_snap(&traces[i]->snaps[j]);
    }
    arrfree(traces[i]->relocs);
    arrfree(traces[i]->ops);
    arrfree(traces[i]->consts);
    arrfree(traces[i]->snaps);
    free(traces[i]);
  }
  arrfree(traces);
}
