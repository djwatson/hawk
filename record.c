#include "record.h"
#include "asm_x64.h"  // for REG_NONE, asm_jit, reg_names
#include "bytecode.h" // for INS_A, INS_B, INS_OP, INS_C, INS_D, bcfunc
#include "ir.h"       // for ir_ins, trace_s, ir_ins_op, ir_ins::(anonymous...
#include "opcodes.h"
#include "snap.h" // for add_snap, snap_replay
#include "third-party/stb_ds.h"
#include "types.h"  // for CONS_TAG, FALSE_REP, SYMBOL_TAG, symbol, CLOSU...
#include "vm.h"     // for find_func_for_frame, hotmap_mask, hotmap_sz
#include "defs.h"
#include <assert.h> // for assert
#include <stdbool.h>
#include <stdint.h> // for uint32_t
#include <stdio.h>  // for printf
#include <stdlib.h> // for exit
#include <string.h> // for NULL, memmove, size_t

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

long func;
int regs_list[257];
int *regs = &regs_list[1];
snap_s *side_exit = nullptr;
static trace_s *parent = nullptr;
static uint8_t unroll = 0;

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

void penalty_pc(uint32_t *pc) {
  uint32_t i = 0;
  for (; i < blacklist_slot; i++) {
    if (blacklist[i].pc == pc) {
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
        // printf("Blacklist cnt now %i slot %i sz %i\n", blacklist[i].cnt, i,
        // blacklist_slot);
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
  }

  // Didn't find it, add it to the list.
  if (i < BLACKLIST_SZ) {
    blacklist[i].pc = pc;
    blacklist[i].cnt = 1;
    blacklist_slot++;
  } else {
    printf("BLACKLIST EVICT\n");
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

void print_const_or_val(int i, trace_s *ctrace) {
  if ((i & IR_CONST_BIAS) != 0) {
    long c = ctrace->consts[i - IR_CONST_BIAS];
    int type = (int)(c & 0x7);
    if (type == 0) {
      printf("\e[1;35m%li\e[m", c >> 3);
    } else if (type == CLOSURE_TAG) {
      printf("\e[1;31m<closure>\e[m");
    } else if (c == FALSE_REP) {
      printf("\e[1;35m#f\e[m");
    } else if (c == TRUE_REP) {
      printf("\e[1;35m#t\e[m");
    } else if (c == NIL_TAG) {
      printf("\e[1;35mnil\e[m");
    } else if (type == CONS_TAG) {
      printf("\e[1;35mcons\e[m");
    } else if (type == FLONUM_TAG) {
      printf("\e[1;35m%f\e[m", ((flonum_s *)c - FLONUM_TAG)->x);
    } else if ((c & IMMEDIATE_MASK) == CHAR_TAG) {
      printf("'%c'", (char)(c >> 8));
    } else if ((c & IMMEDIATE_MASK) == EOF_TAG) {
      printf("eof");
    } else if ((c & IMMEDIATE_MASK) == NIL_TAG) {
      printf("nil");
    } else if (type == SYMBOL_TAG) {
      string_s* sym_name = (string_s*)(((symbol *)(c-SYMBOL_TAG))->name - PTR_TAG);
      printf("\e[1;35m%s\e[m", sym_name->str);
    } else if (type == PTR_TAG) {
      printf("ptr");
    } else if (type == LITERAL_TAG) {
      printf("frame");
    } else {
      assert(false);
    }
  } else {
    printf("%04d", i);
  }
}

void dump_trace(trace_s *ctrace) {
  unsigned long cur_snap = 0;
  for (size_t i = 0; i < arrlen(ctrace->ops) + 1 /* extra snap */; i++) {
    // Print any snap
    while ((cur_snap < arrlen(ctrace->snaps)) &&
           ctrace->snaps[cur_snap].ir == i) {

      auto snap = &ctrace->snaps[cur_snap];
      printf("SNAP[ir=%i pc=%lx off=%i", snap->ir, (long)snap->pc,
             snap->offset);
      for (uint64_t j = 0; j < arrlen(snap->slots); j++) {
        auto entry = &snap->slots[j];
        printf(" %i=", entry->slot);
        print_const_or_val(entry->val, ctrace);
      }
      printf("]\n");
      cur_snap++;
    }
    if (i == arrlen(ctrace->ops)) {
      break;
    }

    auto op = ctrace->ops[i];
    printf("%04zu %s ", i, reg_names[op.reg]);

    if (op.slot != SLOT_NONE) {
      printf("\e[1;31m[%i]\e[m ", op.slot);
    } else {
      printf("    ");
    }
    printf("%c\t", (op.type & IR_INS_TYPE_GUARD) != 0 ? '>' : ' ');
    auto t = op.type & ~IR_INS_TYPE_GUARD;
    if (t == FIXNUM_TAG) {
      printf("\e[1;35mfix \e[m ");
    } else if (t == CLOSURE_TAG) {
      printf("\e[1;31mclo \e[m ");
    } else if (t == CONS_TAG) {
      printf("\e[1;34mcons\e[m ");
    } else if (t == FLONUM_TAG) {
      printf("\e[1;34mflo \e[m ");
    } else if (t == SYMBOL_TAG) {
      printf("\e[1;34msym \e[m ");
    } else if ((op.type & ~IR_INS_TYPE_GUARD) == UNDEFINED_TAG) {
      printf("     ");
    } else if (t == BOOL_TAG) {
      printf("\e[1;34mbool\e[m ");
    } else if (t == NIL_TAG) {
      printf("\e[1;34mnil \e[m ");
    } else if (t == EOF_TAG) {
      printf("\e[1;34meof \e[m ");
    } else if (t == LITERAL_TAG) {
      printf("\e[1;34mlit \e[m ");
      assert(false);
    } else if (t == STRING_TAG) {
      printf("\e[1;34mstr \e[m ");
    } else if (t == VECTOR_TAG) {
      printf("\e[1;34mvec \e[m ");
    } else if (t == PORT_TAG) {
      printf("\e[1;34mport\e[m ");
    } else if (t == BOX_TAG) {
      printf("\e[1;34mbox \e[m ");
    } else if (t == CONT_TAG) {
      printf("\e[1;34mcont\e[m ");
    } else if (t == PTR_TAG) {
      printf("\e[1;34mptr \e[m ");

    } else if (t == CHAR_TAG) {
      printf("\e[1;34mchar\e[m ");
    } else if (t == UNDEFINED_TAG) {
    } else {
      /* printf("UNKNOWN TAG %i\n", t); */
      /* fflush(stdout); */
      printf("\e[1;34mUNK \e[m ");
      /* assert(false); */
    }
    printf("%s ", ir_names[(int)op.op]);
    switch (op.op) {
    case IR_FLUSH:
      break;
    case IR_KFIX:
    case IR_ARG:
    case IR_LOAD:
    case IR_CHGTYPE:
    case IR_SLOAD: {
      print_const_or_val(op.op1, ctrace);
      break;
    }
    case IR_GGET: {
      auto *s = (symbol *)(ctrace->consts[op.op1 - IR_CONST_BIAS] - SYMBOL_TAG);
      string_s* sym_name = (string_s*)(s->name - PTR_TAG);
      printf("%s", sym_name->str);
      break;
    }
    case IR_GSET: {
      auto *s = (symbol *)(ctrace->consts[op.op1 - IR_CONST_BIAS] - SYMBOL_TAG);
      string_s* sym_name = (string_s*)(s->name - PTR_TAG);
      printf("%s ", sym_name->str);
      print_const_or_val(op.op2, ctrace);
      break;
    }
    case IR_ALLOC: {
      print_const_or_val(op.op1, ctrace);
      printf(" type %i", op.op2);
      break;
    }
    case IR_RET:
    case IR_PHI:
    case IR_SUB:
    case IR_ADD:
    case IR_DIV:
    case IR_MUL:
    case IR_REM:
    case IR_EQ:
    case IR_NE:
    case IR_GE:
    case IR_LT:
    case IR_GT:
    case IR_LE:
    case IR_STORE:
    case IR_ABC:
    case IR_VREF:
    case IR_CALLXS:
    case IR_CCRES:
    case IR_CARG:
    case IR_STRST:
    case IR_STRLD:
    case IR_AND:
    case IR_STRREF: {
      print_const_or_val(op.op1, ctrace);
      printf(" ");
      print_const_or_val(op.op2, ctrace);
      break;
    }
    case IR_SHR:
    case IR_REF: {
      print_const_or_val(op.op1, ctrace);
      printf(" offset %i", op.op2);
      break;
    }
    case IR_LOOP: {
      printf("----------------");
      break;
    }
    default:
      printf("Can't dump_trace ir type: %s\n", ir_names[(int)op.op]);
      exit(-1);
    }
    printf("\n");
  }
}

void record_side(trace_s *p, snap_s *side) {
  parent = p;
  side_exit = side;
}

void record_abort();
void record_start(unsigned int *pc, long *frame) {
  trace = malloc(sizeof(trace_s));
  trace->ops = NULL;
  trace->consts = NULL;
  trace->relocs = NULL;
  trace->snaps = NULL;
  trace->link = -1;
  trace->startpc = *pc;
  trace->num = arrlen(traces);
  trace->fn = NULL;
  trace_state = START;
  unroll = 0;
  func = (long)find_func_for_frame(pc);
  assert(func);
  if (verbose) {
    printf("Record start %i at %s func %s\n", trace->num,
           ins_names[INS_OP(*pc)], ((bcfunc *)func)->name);
    if (parent != nullptr) {
      printf("Parent %i\n", parent->num);
    }
  }
  pc_start = pc;
  instr_count = 0;
  depth = 0;
  regs = &regs_list[1];
  for (int i = 0; i < sizeof(regs_list) / sizeof(regs_list[0]); i++) {
    regs_list[i] = -1;
  }

  if (side_exit != nullptr) {
    snap_replay(&regs, side_exit, parent, trace, frame, &depth);
  }
  auto next_pc = pc;
  if (INS_OP(*pc) == FUNC || INS_OP(*pc) == LOOP) {
    next_pc = pc + 1;
  }
  if (INS_OP(*pc) == CLFUNC) {
    next_pc = pc + 2;
  }
  add_snap(regs_list, (int)(regs - regs_list - 1), trace, next_pc, depth);
}

extern int joff;
extern unsigned TRACE_MAX;

void record_stop(unsigned int *pc, long *frame, int link) {
  auto offset = regs - regs_list - 1;
  add_snap(regs_list, (int)offset, trace, pc, depth);
  if (link == (int)arrlen(traces) && offset == 0) {
    // Attempt to loop-fiy it.
    // opt_loop(trace, regs);
  }

  // if (arrlen(trace->ops) <= 3) {
  //   printf("Record abort: trace too small\n");
  //   record_abort();
  //   return;
  // }

  pendpatch();

  if (side_exit != nullptr) {
    side_exit->link = arrlen(traces);
    if (verbose)
      printf("Hooking to parent trace\n");
  } else {
    auto op = INS_OP(*pc_start);
    if (op != RET1 && op != LOOP) {
      *pc_start = CODE_D(JFUNC, INS_A(*pc_start), arrlen(traces));
      if (verbose)
        printf("Installing JFUNC\n");
    } else {
      *pc_start = CODE_D(JLOOP, 0, arrlen(traces));
      if (verbose)
        printf("Installing JLOOP\n");
    }
  }
  if (verbose)
    printf("Installing trace %li\n", arrlen(traces));

  trace->link = link;
  arrput(traces, trace);

  //    dump_trace(trace);
  asm_jit(trace, side_exit, parent);
  if (verbose) {
    dump_trace(trace);
  }

  trace_state = OFF;
  side_exit = nullptr;
  arrfree(downrec);
  trace = nullptr;
  parent = nullptr;
  // joff = 1;
}

void record_abort() {
  if (!parent) {
    penalty_pc(pc_start);
  }
  // TODO separate func
  for(uint64_t i = 0; i < arrlen(trace->snaps); i++) {
    free_snap(&trace->snaps[i]);
  }
  arrfree(trace->consts);
  arrfree(trace->relocs);
  arrfree(trace->ops);
  arrfree(trace->snaps);
  
  pendpatch();
  free(trace);
  trace = nullptr;
  trace_state = OFF;
  side_exit = nullptr;
  arrfree(downrec);
  parent = nullptr;
}

int record(unsigned int *pc, long *frame, long argcnt) {
  if (arrlen(traces) >= TRACE_MAX) {
    return 1;
  }
  switch (trace_state) {
  case OFF: {
    // TODO fix?
    if (INS_OP(*pc) == JFUNC && side_exit == nullptr) {
      // printf("CAN'T RECORD TO JFUNC\n");
      return 1;
    }
    record_start(pc, frame);
    auto res = record_instr(pc, frame, argcnt);
    if (trace_state == START) {
      trace_state = TRACING;
    }
    return res;
    break;
  }
  case TRACING: {
    pendpatch();
    auto res = record_instr(pc, frame, argcnt);
    return res;
    break;
  }
  default: {
    printf("BAD TRACE STATE %i\n", trace_state);
    exit(-1);
    return 1;
  }
  }
}

// Convert a runtime object type to an IR type.
// Use tag bits.  If it's a literal, use IMMEDIATE_MASK.
// If it's a PTR_TAG, follow ptr and use tag bits there.
//
// Currently depends on tag being less than 7 bits total.
// TODO top bit is IR_INS_TYPE_GUARD, this should be part
//      of the load instruction instead.
// TODO: for records we may need a different strategy.
uint8_t get_object_ir_type(int64_t obj) {
  uint8_t t;
  if ((obj & TAG_MASK) == PTR_TAG) {
    int64_t *objp = (int64_t *)(obj - PTR_TAG);
    t = (*objp) & IMMEDIATE_MASK;
  } else if ((obj & TAG_MASK) == LITERAL_TAG) {
    t = obj & IMMEDIATE_MASK;
  } else {
    t = obj & TAG_MASK;
  }
  if (t == PTR_TAG) {
    assert(false);
  }
  return t;
}

int record_stack_load(int slot, const long *frame) {
  if (regs[slot] == -1) {
    // Guard on type
    auto type = get_object_ir_type(frame[slot]);

    regs[slot] =
        push_ir(trace, IR_SLOAD, slot, IR_NONE, IR_INS_TYPE_GUARD | type);
  }
  return regs[slot];
}

// Note: Does not add snap after!  Add if not at end of trace.
void record_funcv(uint32_t i, uint32_t *pc, long* frame, long argcnt) {
  // Otherwise we're on-trace, and the last IR was a call.
  auto ra = INS_A(i);
  auto cnt = argcnt - ra;
  // Build a list from ra of cnt length.
    
  // Load everything first, so that we don't get a guard failure
  // before alloc.
  // TODO: when typechecks are lazy, this can be done inline, since it's just
  // stored in a list and doesn't need a typecheck.
  uint16_t* locs = NULL;
  for(uint32_t j = ra + cnt - 1; j >= ra; j--) {
    arrput(locs, record_stack_load(j, frame));
  }
  add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc, depth);
  trace->snaps[arrlen(trace->snaps) - 1].argcnt = argcnt;
  //  TODO this forces a side exit without recording.
  //   Put GC inline in generated code?  Would have to flush
  //   all registers to stack.
  trace->snaps[arrlen(trace->snaps) - 1].exits = 255;

  // Build the list.
  auto knum = arrlen(trace->consts);
  arrput(trace->consts, NIL_TAG);
  uint16_t prev = knum | IR_CONST_BIAS;
  for(uint32_t j = 0; j < cnt; j++) {
    knum = arrlen(trace->consts);
    arrput(trace->consts, sizeof(cons_s) << 3);
    auto cell = push_ir(trace, IR_ALLOC, knum | IR_CONST_BIAS, CONS_TAG,
                        CONS_TAG);
    auto ref = push_ir(trace, IR_REF, cell, 8 - CONS_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, locs[j], UNDEFINED_TAG);
    ref = push_ir(trace, IR_REF, cell, 8 + 8 - CONS_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, prev, UNDEFINED_TAG);
    prev = cell;
  }
  regs[INS_A(i)] = prev;
  arrfree(locs);
}

void check_emit_funcv(uint32_t startpc, uint32_t* pc, long* frame, long argcnt) {
  if (INS_OP(startpc) == FUNCV || INS_OP(startpc) == CLFUNCV) {
    auto ra = INS_A(startpc);
    //printf("NEEDS FUNCV-ifying %i %li\n", ra, argcnt-ra);
    record_funcv(startpc, pc, frame, argcnt);
  }
}

extern unsigned char hotmap[hotmap_sz];
int record_instr(unsigned int *pc, long *frame, long argcnt) {
  unsigned int i = *pc;

  if (INS_OP(i) == LOOP) {
    for (int *pos = &regs[INS_A(i) + INS_B(i)]; pos < &regs_list[257]; pos++) {
      *pos = -1;
    }
  }
  if ((pc == pc_start) && (depth == 0) && (trace_state == TRACING) &&
      INS_OP(trace->startpc) != RET1 && parent == nullptr) {
    if (INS_OP(*pc) == CLFUNC && argcnt != INS_A(*pc)) {
    } else if (INS_OP(*pc) == CLFUNCV && argcnt < INS_A(*pc)) {
    } else {
      if (verbose)
        printf("Record stop loop\n");
      check_emit_funcv(trace->startpc, pc, frame, argcnt);
      record_stop(pc, frame, arrlen(traces));
      return 1;
    }
  }

  instr_count++;
  if (verbose) {
    for (int j = 0; j < depth; j++) {
      printf(" . ");
    }
    printf("%lx %s %i %i %i\n", (long)pc, ins_names[INS_OP(i)], INS_A(i),
           INS_B(i), INS_C(i));
  }
  switch (INS_OP(i)) {
  case ILOOP: {
    break;
  }
  case LOOP: {
    // TODO check the way luajit does it
    if (arrlen(trace->ops) != 0 && !parent || (unroll++ >= 3)) {
      if (!parent) {
        if (verbose)
          printf("Record abort: Root trace hit untraced loop\n");
      } else {
        if (verbose)
          printf("Record abort: Unroll limit reached in loop for side trace\n");
      }
      hotmap[(((long)pc) >> 2) & hotmap_mask] = 1;
      record_abort();
      return 1;
    }
    break;
  }
  case CLFUNCV:
  case FUNCV: {
    // TODO: We could do build_list before at start of trace
    if (arrlen(trace->ops) == 0) {
      /* printf("Record abort: Can't start at FUNCV\n"); */
      /* record_abort(); */
      /* return 1; */
      break;
    }
    record_funcv(i, pc, frame, argcnt);
    if (INS_OP(i) == CLFUNCV) {
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 2, depth);
    } else {
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);
    }
    break;
  }
  case ICLFUNC:
  case CLFUNC:
  case IFUNC:
  case FUNC: {
    // TODO this is for register-based arguments
    // if (arrlen(trace->ops) == 0) {
    //   for(unsigned arg = 0; arg < INS_A(*pc); arg++) {
    // 	ir_ins ins;
    // 	ins.reg = REG_NONE;
    // 	ins.op1 = arg;
    // 	ins.op = IR_ARG;
    // 	// Guard on type
    // 	auto type = frame[arg] & 0x7;
    // 	ins.type = type;

    // 	regs[arg] = arrlen(trace->ops);
    // 	arrput(trace->ops, ins);

    //   }
    //}
    // TODO: argcheck?
    break;
  }
  case CALLCC: {
    // TODO: this snap and flush only need things below the current frame.
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc, depth);
    trace->snaps[arrlen(trace->snaps) - 1].exits = 255;
    auto op1 = push_ir(trace, IR_FLUSH, 0, 0, UNDEFINED_TAG);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (long)vm_callcc);
    auto cont = push_ir(trace, IR_CALLXS, op1, knum | IR_CONST_BIAS, CONT_TAG);
    // TODO check GC result
    regs[INS_A(i)] = cont;
    knum = arrlen(trace->consts);
    arrput(trace->consts, FALSE_REP);
    push_ir(trace, IR_NE, cont, knum | IR_CONST_BIAS, UNDEFINED_TAG | IR_INS_TYPE_GUARD);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc+1, depth);
    break;
  }
  case CALLCC_RESUME: {
    auto c = record_stack_load(INS_B(i), frame);
    auto result = record_stack_load(INS_C(i), frame);
	
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (long)vm_cc_resume);
    push_ir(trace, IR_CCRES, c, knum | IR_CONST_BIAS, UNDEFINED_TAG);

    // TODO: If the callcc exists in the same trace,
    //       we could optimize here and just pop depth/regs
    //       to the right place also.  I.e. callcc is just
    //       being used as a non-local return, and it's still
    //       on the stack.
      
    // Guard we are going to the right place, almost the same as RET.
    closure_s* cont = (closure_s*)(frame[INS_B(i)] - PTR_TAG);
    auto *old_pc = (unsigned int *)cont->v[(cont->len >> 3) - 1];
    auto frame_off = INS_A(*(old_pc - 1));
    
    // TODO maybe also check for downrec?  Same as RET
    depth = 0;
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc, depth);
    regs = &regs_list[1];
    for (int j = 0; j < sizeof(regs_list) / sizeof(regs_list[0]); j++) {
      regs_list[j] = -1;
    }
    regs[frame_off] = result;
    knum = arrlen(trace->consts);
    arrput(trace->consts, (long)old_pc);
    auto knum2 = arrlen(trace->consts);
    arrput(trace->consts, (frame_off + 1) << 3);
    push_ir(trace, IR_RET, knum | IR_CONST_BIAS, knum2 | IR_CONST_BIAS,
	    IR_INS_TYPE_GUARD | 0x5);

    add_snap(regs_list, (int)(regs - regs_list - 1), trace,
	     (uint32_t *)old_pc, depth);
    break;
  }
  case IRET1:
  case RET1: {
    if (depth == 0) {
      auto *old_pc = (unsigned int *)frame[-1];
      if (INS_OP(*pc_start) == RET1 || side_exit != nullptr) {
        int cnt = 0;
        for (uint64_t p = 0; p < arrlen(downrec); p++) {
          if (downrec[p] == pc) {
            cnt++;
          }
        }
        if (cnt != 0) {
          if (side_exit != nullptr && INS_OP(i) != IRET1) {
            if (verbose)
              printf("Record abort: Potential down-recursion, restarting\n");
            record_abort();
            record_start(pc, frame);
            record_instr(pc, frame, 0);
            trace_state = TRACING;
            break;
          }
          if (pc == pc_start && !side_exit) {
            if (verbose)
              printf("Record stop downrec\n");
            record_stop(pc, frame, arrlen(traces));
          } else {
            if (verbose)
              printf("Record abort downrec\n");
            record_abort();
          }
          return 1;
        }
        arrput(downrec, pc);

        auto result = record_stack_load(INS_A(i), frame);
        // Guard down func type
        add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc, depth);

        auto frame_off = INS_A(*(old_pc - 1));
        // printf("Continue down recursion, frame offset %i\n", frame_off);

	// TODO can we remove this?
        memmove(&regs[frame_off + 1], &regs[0],
                sizeof(int) * (256 - (frame_off + 1)));
        regs[frame_off] = result;
        for (unsigned j = 0; j < frame_off; j++) {
          regs[j] = -1;
        }

        auto knum = arrlen(trace->consts);
        arrput(trace->consts, (long)old_pc);
        auto knum2 = arrlen(trace->consts);
        arrput(trace->consts, (frame_off + 1) << 3);
        push_ir(trace, IR_RET, knum | IR_CONST_BIAS, knum2 | IR_CONST_BIAS,
                IR_INS_TYPE_GUARD | 0x5);

        add_snap(regs_list, (int)(regs - regs_list - 1), trace,
                 (uint32_t *)frame[-1], depth);
        // TODO retdepth
      } else {
        if (INS_OP(trace->startpc) == LOOP && parent == nullptr) {
          if (verbose)
            printf("Record abort: Loop root trace exited loop\n");
          record_abort();
        } else {
          if (verbose)
            printf("Record stop return\n");
          // record_stack_load(INS_A(i), frame);
          record_stop(pc, frame, -1);
        }
        return 1;
      }
    } else if (depth > 0) {
      depth--;
      regs[-1] = regs[INS_A(i)];
      for (int j = (int)(regs - regs_list); j < 257; j++) {
        regs_list[j] = -1;
      }
      auto *old_pc = (unsigned int *)frame[-1];
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
  case CALL: {
    for (int j = INS_A(i) + 1; j < INS_A(i) + INS_B(i); j++) {
      regs[j] = record_stack_load(j, frame);
    }
    {
      auto clo = record_stack_load(INS_A(i) + 1, frame);
      auto ref = push_ir(trace, IR_REF, clo, 16 - CLOSURE_TAG, UNDEFINED_TAG);
      auto fun = push_ir(trace, IR_LOAD, ref, 0, 0);
      regs[INS_A(i)] = fun;
      auto cl = frame[INS_A(i) + 1];
      auto closure = (closure_s *)(cl - CLOSURE_TAG);
      auto knum = arrlen(trace->consts);
      arrput(trace->consts, closure->v[0]);
      push_ir(trace, IR_EQ, fun, knum | IR_CONST_BIAS, IR_INS_TYPE_GUARD);
    }
    /* // Check call type */
    /* { */
    /*   auto v = frame[INS_A(i) + 1]; */
    /*   auto knum = arrlen(trace->consts); */
    /*   arrput(trace->consts, v); */
    /*   ir_ins ins; */
    /*   ins.reg = REG_NONE; */
    /*   ins.op1 = record_stack_load(INS_A(i) + 1, frame); */
    /*   ins.op2 = knum | IR_CONST_BIAS; */
    /*   ins.op = IR_EQ; */
    /*   // TODO magic number */
    /*   ins.type = IR_INS_TYPE_GUARD | 0x5; */
    /*   arrput(trace->ops, ins); */
    /* } */
    long cnt = 0;
    auto *p_pc = (uint32_t *)frame[-1];
    for (int d = depth; d > 0; d--) {
      if (p_pc == pc + 1) {
        cnt++;
      }
      p_pc = (uint32_t *)frame[-1];
    }

    // Setup frame
    depth++;
    // Push PC link as const
    {
      auto knum = (int)arrlen(trace->consts);
      arrput(trace->consts, ((long)(pc + 1)));
      regs[INS_A(i)] = knum | IR_CONST_BIAS; // TODO set PC
    }

    // Increment regs
    assert(regs >= regs_list);
    regs += INS_A(i) + 1;
    assert(regs >= regs_list);

    if (cnt >= UNROLL_LIMIT) {
      auto v = frame[INS_A(i) + 1];
      auto *closure = (closure_s *)(v - CLOSURE_TAG);
      auto *cfunc = (bcfunc *)closure->v[0];
      auto *target = cfunc->code;
      if (target == pc_start) {
        if (verbose)
          printf("Record stop up-recursion\n");
	check_emit_funcv(trace->startpc, pc, frame, argcnt);
        record_stop(target, frame, arrlen(traces));
        return 1;
      } // TODO fix flush
      pendpatch();
      bool abort = false;
      if (INS_OP(cfunc->code[0]) == JFUNC) {
        // Check if it is already up-recursion (i.e. a side trace failed here)
        auto sl_trace = trace_cache_get(INS_D(cfunc->code[0]));
        if (sl_trace->link != INS_D(cfunc->code[0])) {
          if (verbose)
            printf("Flushing trace\n");
          cfunc->code[0] = traces[INS_D(cfunc->code[0])]->startpc;
          hotmap[(((long)pc) >> 2) & hotmap_mask] = 1;
          abort = true;
        }
      } else {
        abort = true;
      }
      if (abort) {
        // TODO this isn't in luajit? fails with side exit without?
        hotmap[(((long)cfunc->code[0]) >> 2) & hotmap_mask] = 1;
        if (verbose)
          printf("Record abort: unroll limit reached\n");
        record_abort();
        return 1;
      }
    }
    break;
  }
  case KSHORT: {
    int64_t k = ((int16_t)INS_D(i)) << 3;
    auto reg = INS_A(i);
    regs[reg] = arrlen(trace->consts) | IR_CONST_BIAS;
    arrput(trace->consts, k);
    break;
  }
  case STRING_SYMBOL: {
    // TODO snapshots
    auto op1 = record_stack_load(INS_B(i), frame);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (long)vm_string_symbol);
    auto sym = push_ir(trace, IR_CALLXS, op1, knum | IR_CONST_BIAS, SYMBOL_TAG);
    regs[INS_A(i)] = sym;
    knum = arrlen(trace->consts);
    arrput(trace->consts, FALSE_REP);
    push_ir(trace, IR_NE, sym, knum | IR_CONST_BIAS, UNDEFINED_TAG | IR_INS_TYPE_GUARD);
    break;
  }
  case SYMBOL_STRING: {
    auto op1 = record_stack_load(INS_B(i), frame);
    auto ref = push_ir(trace, IR_REF, op1, 8 - SYMBOL_TAG, UNDEFINED_TAG);
    regs[INS_A(i)] = push_ir(trace, IR_LOAD, ref, 0, STRING_TAG);
    break;
  }
  case CHAR_INTEGER: {
    auto op1 = record_stack_load(INS_B(i), frame);
    regs[INS_A(i)] = push_ir(trace, IR_SHR, op1, 5, FIXNUM_TAG);
    break;
  }
  case INTEGER_CHAR: {
    auto op1 = record_stack_load(INS_B(i), frame);
    if (get_object_ir_type(frame[INS_B(i)]) != FIXNUM_TAG) {
      printf("Record abort: integer->char with non-char");
      record_abort();
      return 1;
    }
    regs[INS_A(i)] = push_ir(trace, IR_CHGTYPE, op1, FIXNUM_TAG, CHAR_TAG);
    break;
  }
  case JISF: {
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, FALSE_REP);
    uint32_t *next_pc;
    ir_ins_op op;
    auto op1 = record_stack_load(INS_B(i), frame);
    if (frame[INS_B(i)] == FALSE_REP) {
      op = IR_EQ;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 2, depth);
      next_pc = pc + INS_D(*(pc + 1)) + 1;
    } else {
      op = IR_NE;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace,
               pc + INS_D(*(pc + 1)) + 1, depth);
      next_pc = pc + 2;
    }
    push_ir(trace, op, op1, knum | IR_CONST_BIAS, IR_INS_TYPE_GUARD);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, next_pc, depth);
    break;
  }
  case JIST: {
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, FALSE_REP);
    ir_ins_op op;
    uint32_t *next_pc;
    auto op1 = record_stack_load(INS_B(i), frame);
    if (frame[INS_B(i)] == FALSE_REP) {
      op = IR_EQ;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + INS_D(*(pc + 1)) + 1, depth);
      next_pc = pc + 2;
    } else {
      op = IR_NE;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 2, depth);
      next_pc = pc + INS_D(*(pc + 1)) + 1;
    }
    push_ir(trace, op, op1, knum | IR_CONST_BIAS,  IR_INS_TYPE_GUARD);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, next_pc, depth);
    break;
  }
  case JISLT: {
    uint32_t *next_pc;
    ir_ins_op op;
    if (frame[INS_B(i)] < frame[INS_C(i)]) {
      op = IR_LT;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace,
               pc + INS_D(*(pc + 1)) + 1, depth);
      next_pc = pc + 2;
    } else {
      op = IR_GE;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 2, depth);
      next_pc = pc + INS_D(*(pc + 1)) + 1;
    }
    uint8_t type;
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t op2 = record_stack_load(INS_C(i), frame);
    if (op1 >= IR_CONST_BIAS) {
      type = trace->consts[op1 - IR_CONST_BIAS] & TAG_MASK;
    } else {
      type = trace->ops[op1].type & ~IR_INS_TYPE_GUARD;
    }
    if (type != 0) {
      if (verbose)
        printf("Record abort: Only int supported in trace: %i\n", type);
      record_abort();
      return 1;
    }
    push_ir(trace, op, op1, op2, type);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, next_pc, depth);
    break;
  }
  case JISGT: {
    uint32_t *next_pc;
    ir_ins_op op;
    if (frame[INS_B(i)] > frame[INS_C(i)]) {
      op = IR_GT;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace,
               pc + INS_D(*(pc + 1)) + 1, depth);
      next_pc = pc + 2;
    } else {
      op = IR_LE;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 2, depth);
      next_pc = pc + INS_D(*(pc + 1)) + 1;
    }
    uint8_t type;
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t op2 = record_stack_load(INS_C(i), frame);
    if (op1 >= IR_CONST_BIAS) {
      type = trace->consts[op1 - IR_CONST_BIAS] & TAG_MASK;
    } else {
      type = trace->ops[op1].type & ~IR_INS_TYPE_GUARD;
    }
    if (type != 0) {
      if (verbose)
        printf("Record abort: Only int supported in trace: %i\n", type);
      record_abort();
      return 1;
    }
    push_ir(trace, op, op1, op2, type);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, next_pc, depth);
    break;
  }
  case JISGTE: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t op2 = record_stack_load(INS_C(i), frame);
    ir_ins_op op;
    uint32_t *next_pc;
    if (frame[INS_B(i)] >= frame[INS_C(i)]) {
      op = IR_GE;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace,
               pc + INS_D(*(pc + 1)) + 1, depth);
      next_pc = pc + 2;
    } else {
      op = IR_LT;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 2, depth);
      next_pc = pc + INS_D(*(pc + 1)) + 1;
    }
    push_ir(trace, op, op1, op2, IR_INS_TYPE_GUARD);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, next_pc, depth);
    break;
  }
  case JISLTE: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t op2 = record_stack_load(INS_C(i), frame);
    ir_ins_op op;
    uint32_t *next_pc;
    if ((frame[INS_B(i)] & TAG_MASK) == FLONUM_TAG ||
        (frame[INS_C(i)] & TAG_MASK) == FLONUM_TAG) {
      if (verbose)
        printf("Record abort: flonum not supported in jeqv\n");
      record_abort();
      return 1;
    }
    if (frame[INS_B(i)] <= frame[INS_C(i)]) {
      op = IR_LE;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace,
               pc + INS_D(*(pc + 1)) + 1, depth);
      next_pc = pc + 2;
    } else {
      op = IR_GT;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 2, depth);
      next_pc = pc + INS_D(*(pc + 1)) + 1;
    }
    push_ir(trace, op, op1, op2, IR_INS_TYPE_GUARD);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, next_pc, depth);
    break;
  }
  case JEQV:
  case JEQ:
  case JISEQ: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t op2 = record_stack_load(INS_C(i), frame);
    uint32_t *next_pc;
    ir_ins_op op;
    if (INS_OP(i) == JEQV) {
      if ((frame[INS_B(i)] & TAG_MASK) == FLONUM_TAG ||
          (frame[INS_C(i)] & TAG_MASK) == FLONUM_TAG) {
        if (verbose)
          printf("Record abort: flonum not supported in jeqv\n");
        record_abort();
        return 1;
      }
    }
    if (frame[INS_B(i)] == frame[INS_C(i)]) {
      op = IR_EQ;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace,
               pc + INS_D(*(pc + 1)) + 1, depth);
      next_pc = pc + 2;
    } else {
      op = IR_NE;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 2, depth);
      next_pc = pc + INS_D(*(pc + 1)) + 1;
    }
    push_ir(trace, op, op1, op2, IR_INS_TYPE_GUARD);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, next_pc, depth);
    break;
  }
  case JNEQ:
  case JNEQV:
  case JISNEQ: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t op2 = record_stack_load(INS_C(i), frame);
    uint32_t *next_pc;
    ir_ins_op op;
    if (INS_OP(i) == JNEQV) {
      if ((frame[INS_B(i)] & TAG_MASK) == FLONUM_TAG ||
          (frame[INS_C(i)] & TAG_MASK) == FLONUM_TAG) {
        if (verbose)
          printf("Record abort: flonum not supported in jneqv\n");
        record_abort();
        return 1;
      }
    }
    if (INS_OP(i) == JNEQV) {
      if ((frame[INS_B(i)] & TAG_MASK) == FLONUM_TAG ||
          (frame[INS_C(i)] & TAG_MASK) == FLONUM_TAG) {
        if (verbose)
          printf("Record abort: flonum not supported in jneqv\n");
        record_abort();
        return 1;
      }
    }
    if (frame[INS_B(i)] != frame[INS_C(i)]) {
      op = IR_NE;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace,
               pc + INS_D(*(pc + 1)) + 1, depth);
      next_pc = pc + 2;
    } else {
      op = IR_EQ;
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 2, depth);
      next_pc = pc + INS_D(*(pc + 1)) + 1;
    }
    push_ir(trace, op, op1, op2, IR_INS_TYPE_GUARD);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, next_pc, depth);
    break;
  }
  case SET_CDR:
  case SET_CAR: {
    auto box = record_stack_load(INS_A(i), frame);
    auto obj = record_stack_load(INS_B(i), frame);
    uint32_t offset = 0;
    if (INS_OP(i) == SET_CDR) {
      offset = 8;
    }
    auto ref = push_ir(trace, IR_REF, box, 8 + offset - CONS_TAG, 0);
    push_ir(trace, IR_STORE, ref, obj, UNDEFINED_TAG);
    // Modified state, need a snap.
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);
    break;
  }
  case SET_BOX: {
    auto box = record_stack_load(INS_B(i), frame);
    auto obj = record_stack_load(INS_C(i), frame);
    auto ref = push_ir(trace, IR_REF, box, 8 - CONS_TAG, 0);
    push_ir(trace, IR_STORE, ref, obj, UNDEFINED_TAG);
    // Modified state, need a snap.
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);
    break;
  }
  case UNBOX: // DO don't need typecheck
  case CDR:
  case CAR: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t offset = 0;
    uint8_t type;
    if (INS_OP(i) == CAR || INS_OP(i) == UNBOX) {
      // TODO typecheck
      // TODO cleanup
      type = get_object_ir_type(((cons_s *)(frame[INS_B(i)] - CONS_TAG))->a);
    } else {
      type = get_object_ir_type(((cons_s *)(frame[INS_B(i)] - CONS_TAG))->b);
      offset = sizeof(long);
    }
    auto ref =
        push_ir(trace, IR_REF, op1, 8 - CONS_TAG + offset, UNDEFINED_TAG);
    regs[INS_A(i)] =
        push_ir(trace, IR_LOAD, ref, IR_NONE, type | IR_INS_TYPE_GUARD);
    break;
  }
  case ISEQ:
  case EQV:
  case EQ: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t op2 = record_stack_load(INS_C(i), frame);
    int64_t v1 = frame[INS_B(i)];
    int64_t v2 = frame[INS_C(i)];
    int64_t c = FALSE_REP;
    uint8_t op = IR_NE;
    if (v1 == v2) {
      c = TRUE_REP;
      op = IR_EQ;
    }
    if (get_object_ir_type(v1) == FLONUM_TAG ||
	get_object_ir_type(v2) == FLONUM_TAG) {
      if (verbose)
        printf("Record abort: flonum not supported in eqv\n");
      record_abort();
      return 1;
    }
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, c);
    push_ir(trace, op, op1, op2, UNDEFINED_TAG);
    regs[INS_A(i)] = IR_CONST_BIAS + knum;
    break;
  }
  case ISLTE: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t op2 = record_stack_load(INS_C(i), frame);
    int64_t v1 = frame[INS_B(i)];
    int64_t v2 = frame[INS_C(i)];
    if (get_object_ir_type(v1) == FLONUM_TAG ||
        get_object_ir_type(v2) == FLONUM_TAG) {
      if (verbose)
        printf("Record abort: flonum not supported in islt\n");
      record_abort();
      return 1;
    }
    int64_t c = FALSE_REP;
    uint8_t op = IR_GT;
    if (v1 <= v2) {
      c = TRUE_REP;
      op = IR_LE;
    }
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, c);
    push_ir(trace, op, op1, op2, UNDEFINED_TAG);
    regs[INS_A(i)] = IR_CONST_BIAS + knum;
    break;
  }
  case ISLT: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t op2 = record_stack_load(INS_C(i), frame);
    int64_t v1 = frame[INS_B(i)];
    int64_t v2 = frame[INS_C(i)];
    if (get_object_ir_type(v1) == FLONUM_TAG ||
        get_object_ir_type(v2) == FLONUM_TAG) {
      if (verbose)
        printf("Record abort: flonum not supported in islt\n");
      record_abort();
      return 1;
    }
    int64_t c = FALSE_REP;
    uint8_t op = IR_GE;
    if (v1 < v2) {
      c = TRUE_REP;
      op = IR_LT;
    }
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, c);
    push_ir(trace, op, op1, op2, UNDEFINED_TAG);
    regs[INS_A(i)] = IR_CONST_BIAS + knum;
    break;
  }
  case ISGT: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t op2 = record_stack_load(INS_C(i), frame);
    int64_t v1 = frame[INS_B(i)];
    int64_t v2 = frame[INS_C(i)];
    if (get_object_ir_type(v1) == FLONUM_TAG ||
        get_object_ir_type(v2) == FLONUM_TAG) {
      if (verbose)
        printf("Record abort: flonum not supported in islt\n");
      record_abort();
      return 1;
    }
    int64_t c = FALSE_REP;
    uint8_t op = IR_LE;
    if (v1 > v2) {
      c = TRUE_REP;
      op = IR_GT;
    }
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, c);
    push_ir(trace, op, op1, op2, UNDEFINED_TAG);
    regs[INS_A(i)] = IR_CONST_BIAS + knum;
    break;
  }
  case ISGTE: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    uint32_t op2 = record_stack_load(INS_C(i), frame);
    int64_t v1 = frame[INS_B(i)];
    int64_t v2 = frame[INS_C(i)];
    if (get_object_ir_type(v1) == FLONUM_TAG ||
        get_object_ir_type(v2) == FLONUM_TAG) {
      if (verbose)
        printf("Record abort: flonum not supported in islt\n");
      record_abort();
      return 1;
    }
    int64_t c = FALSE_REP;
    uint8_t op = IR_LT;
    if (v1 >= v2) {
      c = TRUE_REP;
      op = IR_GE;
    }
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, c);
    push_ir(trace, op, op1, op2, UNDEFINED_TAG);
    regs[INS_A(i)] = IR_CONST_BIAS + knum;
    break;
  }
  case GUARD: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    int64_t v = frame[INS_B(i)];
    auto type = INS_C(i);
    int64_t c = FALSE_REP;
    auto obj_type = get_object_ir_type(v);
    if (obj_type == type) {
      c = TRUE_REP;
    }
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, c);
    regs[INS_A(i)] = IR_CONST_BIAS + knum;
    break;
  }
  case JNGUARD: {
    record_stack_load(INS_B(i), frame);
    uint8_t type = get_object_ir_type(frame[INS_B(i)]);
    if (type != INS_C(i)) {
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 2, depth);
    } else {
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1 + INS_D(*(pc+1)), depth);
    }
    break;
  }
  case JGUARD: {
    record_stack_load(INS_B(i), frame);
    uint8_t type = get_object_ir_type(frame[INS_B(i)]);
    if (type == INS_C(i)) {
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 2, depth);
    } else {
      add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1 + INS_D(*(pc+1)), depth);
    }
    break;
  }
  case KONST: {
    auto k = const_table[INS_D(i)];
    auto reg = INS_A(i);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, k);
    regs[reg] = IR_CONST_BIAS + knum;
    break;
  }
  case KFUNC: {
    auto k = (long)funcs[INS_D(i)];
    auto reg = INS_A(i);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, k);
    regs[reg] = IR_CONST_BIAS + knum;
    break;
  }
  case VECTOR_SET: {
    auto vec = record_stack_load(INS_A(i), frame);
    auto idx = record_stack_load(INS_B(i), frame);
    auto obj = record_stack_load(INS_C(i), frame);

    push_ir(trace, IR_ABC, vec, idx, IR_INS_TYPE_GUARD);
    auto vref = push_ir(trace, IR_VREF, vec, idx, 0);
    push_ir(trace, IR_STORE, vref, obj, 0);

    // Record state because of IR_STORE
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);

    break;
  }
  case VECTOR_REF: {
    auto vec = record_stack_load(INS_B(i), frame);
    auto idx = record_stack_load(INS_C(i), frame);

    push_ir(trace, IR_ABC, vec, idx, IR_INS_TYPE_GUARD);
    auto vref = push_ir(trace, IR_VREF, vec, idx, 0);

    uint64_t pos = frame[INS_C(i)] >> 3;
    vector_s *vec_d = (vector_s *)(frame[INS_B(i)] - PTR_TAG);
    uint8_t type = get_object_ir_type(vec_d->v[pos]);
    regs[INS_A(i)] = push_ir(trace, IR_LOAD, vref, 0, IR_INS_TYPE_GUARD | type);

    break;
  }
  case STRING_REF: {
    auto str = record_stack_load(INS_B(i), frame);
    auto idx = record_stack_load(INS_C(i), frame);

    push_ir(trace, IR_ABC, str, idx, IR_INS_TYPE_GUARD);
    regs[INS_A(i)] = push_ir(trace, IR_STRLD, str, idx, CHAR_TAG);

    break;
  }
  case STRING_SET: {
    auto str = record_stack_load(INS_A(i), frame);
    auto idx = record_stack_load(INS_B(i), frame);
    auto val = record_stack_load(INS_C(i), frame);

    push_ir(trace, IR_ABC, str, idx, IR_INS_TYPE_GUARD);
    auto ref = push_ir(trace, IR_STRREF, str, idx, 0);
    push_ir(trace, IR_STRST, ref, val, 0);

    break;
  }
  case CLOSURE: {
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc, depth);
    //  TODO this forces a side exit without recording.
    //   Put GC inline in generated code?  Would have to flush
    //   all registers to stack.
    trace->snaps[arrlen(trace->snaps) - 1].exits = 255;
    // TODO fixed closz
    long closz = (frame[INS_A(i) + 1] >> 3) + 1;
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (sizeof(long) * (closz + 2)) << 3);
    auto cell = push_ir(trace, IR_ALLOC, knum | IR_CONST_BIAS, CLOSURE_TAG, CLOSURE_TAG);
    auto ref = push_ir(trace, IR_REF, cell, 8 - CLOSURE_TAG, UNDEFINED_TAG);
    knum = arrlen(trace->consts);
    arrput(trace->consts, (long)closz << 3);
    push_ir(trace, IR_STORE, ref, knum | IR_CONST_BIAS, 0);
    auto a = record_stack_load(INS_A(i), frame);
    // TODO
    // The first value *must* be the function ptr.
    // THe rest of the values are just *something*
    // so that if we abort, there is a valid GC object.
    // Could also be 0-initialized.
    // TODO figure out a way to ensure we always snapshpt
    // after fully setting? I.e. don't abort ever?
    for (long j = 0; j < closz; j++) {
      ref =
          push_ir(trace, IR_REF, cell, 16 + 8 * j - CLOSURE_TAG, UNDEFINED_TAG);
      push_ir(trace, IR_STORE, ref, a, 0);
    }
    regs[INS_A(i)] = cell;
    /* for(unsigned j = 1; j < INS_B(i); j++) { */
    /*   regs[INS_A(i) + j] = -1; */
    /* } */
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);
    break;
  }
  case BOX:
  case CONS: {
    auto a = record_stack_load(INS_B(i), frame);
    int b;
    if (INS_OP(i) == CONS) {
      b = record_stack_load(INS_C(i), frame);
    } else {
      // BOX
      auto knum = arrlen(trace->consts);
      arrput(trace->consts, NIL_TAG);
      b = knum | IR_CONST_BIAS;
    }
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc, depth);
    //  TODO this forces a side exit without recording.
    //   Put GC inline in generated code?  Would have to flush
    //   all registers to stack.
    trace->snaps[arrlen(trace->snaps) - 1].exits = 255;
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, sizeof(cons_s) << 3);
    auto cell = push_ir(trace, IR_ALLOC, knum | IR_CONST_BIAS, CONS_TAG, CONS_TAG);
    regs[INS_A(i)] = cell;
    auto ref = push_ir(trace, IR_REF, cell, 8 - CONS_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, a, UNDEFINED_TAG);
    ref = push_ir(trace, IR_REF, cell, 8 + 8 - CONS_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, b, UNDEFINED_TAG);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);

    break;
  }
  case MAKE_STRING: {
    auto sz = record_stack_load(INS_B(i), frame);
    auto ch = record_stack_load(INS_C(i), frame);

    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc, depth);
    //  TODO this forces a side exit without recording.
    //   Put GC inline in generated code?  Would have to flush
    //   all registers to stack.
    trace->snaps[arrlen(trace->snaps) - 1].exits = 255;
    
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, ((sizeof(long)*2) + 1 + 7 /* ptr align */) << 3);
    auto alloc_sz = push_ir(trace, IR_ADD, sz, knum | IR_CONST_BIAS, FIXNUM_TAG);
    knum = arrlen(trace->consts);
    arrput(trace->consts, (unsigned long)(~TAG_MASK) << 3);
    auto alloc_sz_aligned = push_ir(trace, IR_AND, alloc_sz, knum | IR_CONST_BIAS, FIXNUM_TAG);
    // TODO snaps??
    auto cell = push_ir(trace, IR_ALLOC, alloc_sz_aligned, PTR_TAG, STRING_TAG);

    auto ref = push_ir(trace, IR_REF, cell, 8 - PTR_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, sz, UNDEFINED_TAG);
    regs[INS_A(i)] = cell;

    // Set the string values to ch
    // Basically using memset, because that's what gcc/clang would do.
    // TODO could optimize away if sz = 0 or ch isn't passed (i.e. (make-string 100))
    auto arg = push_ir(trace, IR_CARG, cell, ch, UNDEFINED_TAG);
    knum = arrlen(trace->consts);
    arrput(trace->consts, (long)vm_make_string);
    push_ir(trace, IR_CALLXS, arg, knum | IR_CONST_BIAS, UNDEFINED_TAG);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc+1, depth);

    break;
  }
  case MAKE_VECTOR: {
    auto sz = record_stack_load(INS_B(i), frame);
    auto ch = record_stack_load(INS_C(i), frame);

    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc, depth);
    //  TODO this forces a side exit without recording.
    //   Put GC inline in generated code?  Would have to flush
    //   all registers to stack.
    trace->snaps[arrlen(trace->snaps) - 1].exits = 255;
    
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (2) << 3);
    auto alloc_sz = push_ir(trace, IR_ADD, sz, knum | IR_CONST_BIAS, FIXNUM_TAG);
    knum = arrlen(trace->consts);
    arrput(trace->consts, (unsigned long)(8) << 3);
    auto alloc_sz_aligned = push_ir(trace, IR_MUL, alloc_sz, knum | IR_CONST_BIAS, FIXNUM_TAG);
    // TODO snaps??
    auto cell = push_ir(trace, IR_ALLOC, alloc_sz_aligned, PTR_TAG, VECTOR_TAG);

    auto ref = push_ir(trace, IR_REF, cell, 8 - PTR_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, sz, UNDEFINED_TAG);
    regs[INS_A(i)] = cell;

    auto arg = push_ir(trace, IR_CARG, cell, ch, UNDEFINED_TAG);
    knum = arrlen(trace->consts);
    arrput(trace->consts, (long)vm_make_vector);
    push_ir(trace, IR_CALLXS, arg, knum | IR_CONST_BIAS, UNDEFINED_TAG);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc+1, depth);

    break;
  }
  case VECTOR: {
    auto len = INS_B(i);
    auto reg = INS_A(i);
    int *loaded = NULL;
    for (uint32_t cnt = 0; cnt < len; cnt++) {
      arrput(loaded, record_stack_load(reg + cnt, frame));
    }
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc, depth);
    //  TODO this forces a side exit without recording.
    //   Put GC inline in generated code?  Would have to flush
    //   all registers to stack.
    trace->snaps[arrlen(trace->snaps) - 1].exits = 255;

    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (sizeof(vector_s) + 8 * len) << 3);
    auto cell = push_ir(trace, IR_ALLOC, knum | IR_CONST_BIAS, PTR_TAG,
                        VECTOR_TAG);
    regs[reg] = cell;
    auto ref = push_ir(trace, IR_REF, cell, 8 - PTR_TAG, UNDEFINED_TAG);
    knum = arrlen(trace->consts);
    arrput(trace->consts, (long)(len << 3));
    push_ir(trace, IR_STORE, ref, knum | IR_CONST_BIAS, UNDEFINED_TAG);
    for (uint32_t cnt = 0; cnt < len; cnt++) {
      ref = push_ir(trace, IR_REF, cell, 16 + cnt * 8 - PTR_TAG, UNDEFINED_TAG);
      push_ir(trace, IR_STORE, ref, loaded[cnt], UNDEFINED_TAG);
    }
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);
    arrfree(loaded);

    break;
  }
  case MOV: {
    regs[INS_A(i)] = record_stack_load(INS_B(i), frame);
    // TODO loop moves can clear
    // regs[INS_B(i)] = -1;
    break;
  }
  case READ: {
    port_s *port = (port_s *)(frame[INS_B(i)] - PTR_TAG);
    uint8_t type = CHAR_TAG;
    // TODO peek instead.
    if (port->eof == TRUE_REP) {
      type = EOF_TAG;
    }
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (long)vm_read_char);
    regs[INS_A(i)] =
        push_ir(trace, IR_CALLXS, record_stack_load(INS_B(i), frame),
                knum | IR_CONST_BIAS, type | IR_INS_TYPE_GUARD);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);
    break;
  }
  case PEEK: {
    port_s *port = (port_s *)(frame[INS_B(i)] - PTR_TAG);
    uint8_t type = CHAR_TAG;
    // TODO peek instead.
    if (port->eof == TRUE_REP) {
      type = EOF_TAG;
    }
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (long)vm_peek_char);
    regs[INS_A(i)] =
        push_ir(trace, IR_CALLXS, record_stack_load(INS_B(i), frame),
                knum | IR_CONST_BIAS, type | IR_INS_TYPE_GUARD);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);
    break;
  }
  case WRITE: {
    auto arg = push_ir(trace, IR_CARG, record_stack_load(INS_B(i), frame),
                       record_stack_load(INS_C(i), frame), UNDEFINED_TAG);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (long)vm_write);
    push_ir(trace, IR_CALLXS, arg, knum | IR_CONST_BIAS, UNDEFINED_TAG);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);
    break;
  }
  case GGET: {
    // TODO check it is set?
    long gp = const_table[INS_D(i)];

    auto knum = arrlen(trace->consts);
    arrput(trace->consts, gp);
    symbol *sym = (symbol *)(gp - SYMBOL_TAG);
    uint8_t type = get_object_ir_type(sym->val);
    regs[INS_A(i)] = push_ir(trace, IR_GGET, knum | IR_CONST_BIAS, IR_NONE,
                             type | IR_INS_TYPE_GUARD);
    break;
  }
  case GSET: {
    long gp = const_table[INS_D(i)];
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, gp);
    push_ir(trace, IR_GSET, knum | IR_CONST_BIAS,
            record_stack_load(INS_A(i), frame), UNDEFINED_TAG);
    // We've changed global state, add a snap.
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);
    break;
  }
  case SUBVN: {
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, ((int64_t)((int8_t)INS_C(i))) << 3);
    auto op1 = record_stack_load(INS_B(i), frame);
    uint8_t type = 0;
    if (op1 >= IR_CONST_BIAS) {
      type = trace->consts[op1 - IR_CONST_BIAS] & TAG_MASK;
    } else {
      type = trace->ops[op1].type & ~IR_INS_TYPE_GUARD;
    }
    if (type != 0) {
      if (verbose)
        printf("Record abort: Only int supported in trace: %i\n", type);
      record_abort();
      return 1;
    }
    regs[INS_A(i)] = push_ir(trace, IR_SUB, op1, knum | IR_CONST_BIAS,
                             IR_INS_TYPE_GUARD | type);
    break;
  }
  case ADDVN: {
    // TODO check type
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, ((int64_t)((int8_t)INS_C(i))) << 3);
    auto op1 = record_stack_load(INS_B(i), frame);
    uint8_t type = 0;
    if (op1 >= IR_CONST_BIAS) {
      type = trace->consts[op1 - IR_CONST_BIAS] & TAG_MASK;
    } else {
      type = trace->ops[op1].type & ~IR_INS_TYPE_GUARD;
    }
    if (type != 0) {
      if (verbose)
        printf("Record abort: Only int supported in trace: %i\n", type);
      record_abort();
      return 1;
    }
    regs[INS_A(i)] = push_ir(trace, IR_ADD, op1, knum | IR_CONST_BIAS,
                             type | IR_INS_TYPE_GUARD);
    break;
  }
  case ADDVV: {
    auto op1 = record_stack_load(INS_B(i), frame);
    auto op2 = record_stack_load(INS_C(i), frame);
    // TODO: Assume no type change??
    uint8_t type = 0;
    if (op1 >= IR_CONST_BIAS) {
      type = trace->consts[op1 - IR_CONST_BIAS] & TAG_MASK;
    } else {
      type = trace->ops[op1].type & ~IR_INS_TYPE_GUARD;
    }
    if (type != 0) {
      if (verbose)
        printf("Record abort: Only int supported in trace: %i\n", type);
      record_abort();
      return 1;
    }
    regs[INS_A(i)] = push_ir(trace, IR_ADD, op1, op2, IR_INS_TYPE_GUARD | type);
    break;
  }
  case SUBVV: {
    auto op1 = record_stack_load(INS_B(i), frame);
    auto op2 = record_stack_load(INS_C(i), frame);
    // TODO: Assume no type change??
    uint8_t type = 0;
    if (op1 >= IR_CONST_BIAS) {
      type = trace->consts[op1 - IR_CONST_BIAS] & TAG_MASK;
    } else {
      type = trace->ops[op1].type & ~IR_INS_TYPE_GUARD;
    }
    if (type != 0) {
      if (verbose)
        printf("Record abort: Only int supported in trace: %i\n", type);
      record_abort();
      return 1;
    }
    regs[INS_A(i)] = push_ir(trace, IR_SUB, op1, op2, IR_INS_TYPE_GUARD | type);
    break;
  }
  case MULVV:
  case REM:
  case DIV: {
    auto op1 = record_stack_load(INS_B(i), frame);
    auto op2 = record_stack_load(INS_C(i), frame);
    // TODO: Assume no type change??
    uint8_t type = 0;
    if (get_object_ir_type(frame[INS_B(i)]) != 0 ||
        get_object_ir_type(frame[INS_C(i)]) != 0) {
      if (verbose)
        printf("Record abort: Only int supported in trace: %i\n", type);
      record_abort();
      return 1;
    }
    uint8_t op = IR_DIV;
    if (INS_OP(i) == REM) {
      op = IR_REM;
    } else if (INS_OP(i) == MULVV) {
      op = IR_MUL;
    }
    regs[INS_A(i)] = push_ir(trace, op, op1, op2, type);
    break;
  }
  case EXACT: {
    regs[INS_A(i)] = record_stack_load(INS_B(i), frame);
    auto type = get_object_ir_type(frame[INS_B(i)]);
    if (type != 0) {
      if (verbose)
        printf("Record abort: exact only supports fixnum\n");
      record_abort();
      return 1;
    }
    break;
  }
  case CALLT: {
    // Check call type
    {
      auto clo = record_stack_load(INS_A(i) + 1, frame);
      auto ref = push_ir(trace, IR_REF, clo, 16 - CLOSURE_TAG, UNDEFINED_TAG);
      auto fun = push_ir(trace, IR_LOAD, ref, 0, 0);
      regs[INS_A(i)] = fun;
      auto cl = frame[INS_A(i) + 1];
      auto closure = (closure_s *)(cl - CLOSURE_TAG);
      auto knum = arrlen(trace->consts);
      arrput(trace->consts, closure->v[0]);
      push_ir(trace, IR_EQ, fun, knum | IR_CONST_BIAS, IR_INS_TYPE_GUARD);
    }
    /* { */
    /*   auto v = frame[INS_A(i) + 1]; */
    /*   auto knum = arrlen(trace->consts); */
    /*   arrput(trace->consts, v); */
    /*   ir_ins ins; */
    /*   ins.reg = REG_NONE; */
    /*   ins.op1 = record_stack_load(INS_A(i) + 1, frame); */
    /*   ins.op2 = knum | IR_CONST_BIAS; */
    /*   ins.op = IR_EQ; */
    /*   // TODO magic number */
    /*   ins.type = IR_INS_TYPE_GUARD | 0x5; */
    /*   arrput(trace->ops, ins); */
    /* } */
    // Move args down
    // TODO also chedck func
    for (int j = INS_A(i) + 1; j < INS_A(i) + INS_B(i); j++) {
      regs[j] = record_stack_load(j, frame);
    }
    memmove(&regs[0], &regs[INS_A(i) + 1], sizeof(int) * (INS_B(i) - 1));
    for (int j = INS_B(i) - 1; j < 256; j++) {
      if (&regs[j] >= regs_list + 256) {
        break;
      }
      regs[j] = -1;
    }

    break;
  }
  case STRING_LENGTH:
  case VECTOR_LENGTH: {
    auto vec = record_stack_load(INS_B(i), frame);
    auto ref = push_ir(trace, IR_REF, vec, 8 - PTR_TAG, UNDEFINED_TAG);
    regs[INS_A(i)] = push_ir(trace, IR_LOAD, ref, 0, FIXNUM_TAG);
    break;
  }
  case CLOSURE_GET: {
    auto clo = record_stack_load(INS_B(i), frame);
    auto ref = push_ir(trace, IR_REF, clo,
                       16 + (8 * (1 + INS_C(i))) - CLOSURE_TAG, UNDEFINED_TAG);

    // Note: Closure doesn't necessarily need typecheck since closures are
    // CONST. However, there are some situations where invalid code may hit bad
    // types? I.e. polymorphic functions could do a different STORE type?
    //
    // Actually, this is invalid: closures could close '() or a list, and still
    // be what code is expecting.
    uint64_t pos = INS_C(i) + 1;
    closure_s *clo_d = (closure_s *)(frame[INS_B(i)] - CLOSURE_TAG);
    uint8_t type = get_object_ir_type(clo_d->v[pos]);

    regs[INS_A(i)] = push_ir(trace, IR_LOAD, ref, 0, IR_INS_TYPE_GUARD | type);

    /* // TODO: closure may not be const */
    /* auto fb = frame[INS_B(i)]; */
    /* auto closure = (closure_s *)(fb - CLOSURE_TAG); */

    /* auto knum = (int)arrlen(trace->consts); */
    /* arrput(trace->consts, closure->v[1 + INS_C(i)]); */
    /* regs[INS_A(i)] = knum | IR_CONST_BIAS; */
    break;
  }
  case CLOSURE_SET: {
    auto clo = record_stack_load(INS_A(i), frame);
    auto val = record_stack_load(INS_B(i), frame);
    auto ref = push_ir(trace, IR_REF, clo,
                       16 + (8 * (1 + INS_C(i))) - CLOSURE_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, val, UNDEFINED_TAG);
    break;
  }
  case JMP: {
    break;
  }
  case JFUNC: {

    // Check if it is a returning trace
    auto *ctrace = trace_cache_get(INS_D(i));
    if (INS_OP(ctrace->startpc) == CLFUNC) {
      if (argcnt != INS_A(ctrace->startpc)) {
	// The check will fail, and we will fall through to a later
	// CLFUNC.
        break;
      }
    }
    if (INS_OP(ctrace->startpc) == CLFUNCV) {
      if (argcnt < INS_A(ctrace->startpc)) {
	// The check will fail, and we will fall through to a later
	// CLFUNC.
        break;
      }
    }
    // If it is a returning non-looping trace, trace through it.
    if (ctrace->link == -1) {
      assert(patchpc == nullptr);
      patchpc = pc;
      patchold = *pc;
      *pc = traces[INS_D(*pc)]->startpc;

      // Check if it is a FUNCV and emit a list build if necessary.
      check_emit_funcv(*pc, pc, frame, argcnt);
      break;
    }
    // Otherwise, we're going to link to the JFUNC.
    for (int j = 0; j < INS_A(i); j++) {
      regs[j] = record_stack_load(j, frame);
    }
    if (verbose)
      printf("Record stop JFUNC\n");
    check_emit_funcv(traces[INS_D(i)]->startpc, pc, frame, argcnt);
    record_stop(pc, frame, INS_D(i));
    return 1;
  }
  case JLOOP: {
    auto *ctrace = trace_cache_get(INS_D(i));
    if (side_exit == nullptr && INS_OP(ctrace->startpc) != RET1) {
      if (verbose)
        printf("Record abort: root trace hit loop\n");
      record_abort();
      return 1;
    }
    if (verbose)
      printf("Record stop hit JLOOP\n");
    // NOTE: stack load is for ret1 jloop returns.  Necessary?
    // TODO JLOOp also used for loop, only need to record for RET
    regs[INS_A(i)] = record_stack_load(INS_A(i), frame);
    record_stop(pc, frame, INS_D(i));
    return 1;
  }
  default: {
    bcfunc *fc = find_func_for_frame(pc);
    if (verbose)
      printf("Record abort: NYI: CANT RECORD BYTECODE %s in %s\n",
             ins_names[INS_OP(i)], fc ? fc->name : "???");
    record_abort();
    return 1;
    // exit(-1);
  }
  }
  if (instr_count > 1000) {
    if (verbose)
      printf("Record abort: due to length\n");
    record_abort();
    return 1;
  }
  // if (depth <= -3) {
  //   printf("Record stop [possible down-recursion]\n");
  //   return 1;
  // }
  // TODO check chain for down-recursion
  // TODO this should check regs depth
  if (depth >= 20) {
    if (verbose)
      printf("Record abort: (stack too deep)\n");
    record_abort();
    return 1;
  }
  return 0;
}

trace_s *trace_cache_get(unsigned int tnum) { return traces[tnum]; }

EXPORT void free_trace() {
  if (verbose) {
    printf("Traces: %li\n", arrlen(traces));
  }
  for(uint64_t i = 0; i < arrlen(traces); i++) {
    for(uint64_t j = 0; j < arrlen(traces[i]->snaps); j++) {
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
