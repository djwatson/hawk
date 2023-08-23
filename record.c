#include "record.h"
#include "asm_x64.h"  // for REG_NONE, asm_jit, reg_names
#include "bytecode.h" // for INS_A, INS_B, INS_OP, INS_C, INS_D, bcfunc
#include "ir.h"       // for ir_ins, trace_s, ir_ins_op, ir_ins::(anonymous...
#include "opcodes.h"
#include "snap.h" // for add_snap, snap_replay
#include "third-party/stb_ds.h"
#include "types.h"  // for CONS_TAG, FALSE_REP, SYMBOL_TAG, symbol, CLOSU...
#include "vm.h"     // for find_func_for_frame, hotmap_mask, hotmap_sz
#include <assert.h> // for assert
#include <stdbool.h>
#include <stdint.h> // for uint32_t
#include <stdio.h>  // for printf
#include <stdlib.h> // for exit
#include <string.h> // for NULL, memmove, size_t

#define auto __auto_type
#define nullptr NULL

typedef struct {
  uint32_t *pc;
  uint32_t cnt;
} blacklist_entry;

#define BLACKLIST_MAX 10
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

void penalty_pc(uint32_t* pc) {
  uint32_t i = 0;
  for(; i < blacklist_slot; i++) {
    if (blacklist[i].pc == pc) {
      if (blacklist[i].cnt >= BLACKLIST_MAX) {
	printf("Blacklist pc %p\n", pc);
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
	int64_t next = i+1;
	while(next < blacklist_slot) {
	  blacklist_entry tmp = blacklist[next];
	  blacklist[next-1] = blacklist[next];
	  blacklist[next] = tmp;
	  next++;
	}
	blacklist_slot--;
      } else {
	blacklist[i].cnt++;
	printf("Blacklist cnt now %i slot %i sz %i\n", blacklist[i].cnt, i, blacklist_slot);
	int64_t prev = (int64_t)i-1;
	while(prev >= 0 && blacklist[prev].cnt <= blacklist[prev+1].cnt) {
	  blacklist_entry tmp = blacklist[prev];
	  blacklist[prev] = blacklist[prev+1];
	  blacklist[prev+1] = tmp;
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
    auto c = ctrace->consts[i - IR_CONST_BIAS];
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
      printf("\e[1;35m%f\e[m", ((flonum_s*)c - FLONUM_TAG)->x);
    } else if ((c & IMMEDIATE_MASK) == CHAR_TAG) {
      printf("'%c'", (char)(c >> 8));
    } else if ((c & IMMEDIATE_MASK) == EOF_TAG) {
      printf("eof");
    } else if ((c & IMMEDIATE_MASK) == NIL_TAG) {
      printf("nil");
    } else if (type == SYMBOL_TAG) {
      printf("\e[1;35m%s\e[m", ((symbol*)(c - SYMBOL_TAG))->name->str);
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
    auto t = op.type & TAG_MASK;
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
    } else if (t == LITERAL_TAG) {
      printf("\e[1;34mlit \e[m ");
    } else if (t == PTR_TAG) {
      // TODO
      printf("\e[1;34mptr \e[m ");
    } else {
      //printf("\e[1;34mUNK \e[m ");
      assert(false);
    }
    printf("%s ", ir_names[(int)op.op]);
    switch (op.op) {
    case IR_CAR:
    case IR_CDR:
    case IR_KFIX:
    case IR_ARG:
    case IR_LOAD:
    case IR_SLOAD: {
      print_const_or_val(op.op1, ctrace);
      break;
    }
    case IR_GGET: {
      auto *s = (symbol *)(ctrace->consts[op.op1 - IR_CONST_BIAS] - SYMBOL_TAG);
      printf("%s", s->name->str);
      break;
    }
    case IR_GSET: {
      auto *s = (symbol *)(ctrace->consts[op.op1 - IR_CONST_BIAS] - SYMBOL_TAG);
      printf("%s ", s->name->str);
      print_const_or_val(op.op2, ctrace);
      break;
    }
    case IR_ALLOC: {
      printf("%i type %i", op.op1, op.op2);
      break;
    }
    case IR_RET:
    case IR_PHI:
    case IR_SUB:
    case IR_ADD:
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
    case IR_CARG:
    case IR_STRST:
    case IR_STRLD:
    case IR_STRREF: 
    case IR_CLT: {
      print_const_or_val(op.op1, ctrace);
      printf(" ");
      print_const_or_val(op.op2, ctrace);
      break;
    }
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
  func = (long)find_func_for_frame(pc);
  assert(func);
  printf("Record start %i at %s func %s\n", trace->num, ins_names[INS_OP(*pc)],
         ((bcfunc *)func)->name);
  if (parent != nullptr) {
    printf("Parent %i\n", parent->num);
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
  add_snap(regs_list, (int)(regs - regs_list - 1), trace,
           (INS_OP(*pc) == FUNC || INS_OP(*pc) == LOOP) ? pc + 1 : pc, depth);
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
    printf("Hooking to parent trace\n");
  } else {
    auto op = INS_OP(*pc_start);
    if (op != RET1 && op != LOOP) {
      *pc_start = CODE_D(JFUNC, INS_A(*pc_start), arrlen(traces));
      printf("Installing JFUNC\n");
    } else {
      *pc_start = CODE_D(JLOOP, 0, arrlen(traces));
      printf("Installing JLOOP\n");
    }
  }
  printf("Installing trace %li\n", arrlen(traces));

  trace->link = link;
  arrput(traces, trace);

  //dump_trace(trace);
  asm_jit(trace, side_exit, parent);
  dump_trace(trace);

  trace_state = OFF;
  side_exit = nullptr;
  arrfree(downrec);
  trace = nullptr;
  // joff = 1;
}

void record_abort() {
  if (!parent) {
    penalty_pc(pc_start);
  }
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

int record_stack_load(int slot, const long *frame) {
  if (regs[slot] == -1) {
    // Guard on type
    auto type = frame[slot] & 0x7;
    if (type == LITERAL_TAG) {
      type = frame[slot] & IMMEDIATE_MASK;
    }
    if (type == PTR_TAG) {
      printf("WARNING typecheck ptr\n");
      // TODO
      // assert(false);
    }

    regs[slot] = push_ir(trace, IR_SLOAD, slot, IR_NONE, IR_INS_TYPE_GUARD | type);
  }
  return regs[slot];
}

extern unsigned char hotmap[hotmap_sz];
int record_instr(unsigned int *pc, long *frame, long argcnt) {
  unsigned int i = *pc;

  if (INS_OP(i) == LOOP) {
    for (int *pos = &regs[INS_A(i)]; pos < &regs_list[257]; pos++) {
      *pos = -1;
    }
  } else if (INS_OP(i) == CLFUNC) {
    // If it doesn't match, just continue;
    if (argcnt != INS_A(i)) {
      return 0;
    }
  }
  if ((pc == pc_start) && (depth == 0) && (trace_state == TRACING) &&
      INS_OP(trace->startpc) != RET1 && parent == nullptr) {
    printf("Record stop loop\n");
    record_stop(pc, frame, arrlen(traces));
    return 1;
  }

  instr_count++;
  for (int j = 0; j < depth; j++) {
    printf(" . ");
  }
  printf("%lx %s %i %i %i\n", (long)pc, ins_names[INS_OP(i)], INS_A(i),
         INS_B(i), INS_C(i));
  switch (INS_OP(i)) {
  case LOOP: {
    // TODO check the way luajit does it
    if (arrlen(trace->ops) != 0) {
      printf("Record abort: Trace hit untraced loop\n");
      record_abort();
      return 1;
    }
    // case CLFUNC:
    break;
  }
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
          if (side_exit != nullptr) {
            printf("Record abort: Potential down-recursion, restarting\n");
            record_abort();
            record_start(pc, frame);
            record_instr(pc, frame, 0);
            trace_state = TRACING;
            break;
          }
	  if (pc == pc_start) {
	    printf("Record stop downrec\n");
	    record_stop(pc, frame, arrlen(traces));
	  } else {
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
        printf("Continue down recursion, frame offset %i\n", frame_off);

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
	push_ir(trace, IR_RET, knum | IR_CONST_BIAS, knum2 | IR_CONST_BIAS, IR_INS_TYPE_GUARD | 0x5);

        add_snap(regs_list, (int)(regs - regs_list - 1), trace, (uint32_t *)frame[-1], depth);
        // TODO retdepth
      } else {
        if (INS_OP(trace->startpc) == LOOP && parent == nullptr) {
          printf("Record abort: Loop root trace exited loop\n");
          record_abort();
        } else {
          printf("Record stop return\n");
	  //record_stack_load(INS_A(i), frame);
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
      auto ref = push_ir(trace, IR_REF, clo, 16 - CLOSURE_TAG, 0);
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
        printf("Record stop up-recursion\n");
        record_stop(target, frame, arrlen(traces));
        return 1;
      } // TODO fix flush
      pendpatch();
      if (INS_OP(cfunc->code[0]) == JFUNC) {
	// Check if it is already up-recursion (i.e. a side trace failed here)
	auto sl_trace = trace_cache_get(INS_D(cfunc->code[0]));
	if (sl_trace->link != INS_D(cfunc->code[0])) {
	  printf("Flushing trace\n");
	  cfunc->code[0] = traces[INS_D(cfunc->code[0])]->startpc;
	  hotmap[(((long)pc) >> 2) & hotmap_mask] = 1;
	}
      }
      // TODO this isn't in luajit? fails with side exit without?
      hotmap[(((long)pc) >> 2) & hotmap_mask] = 1;
      printf("Record abort: unroll limit reached\n");
      record_abort();
      return 1;
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
  /* case ISLT: { */
  /*   add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc); */
  /*   auto reg = INS_A(i); */
  /*   ir_ins ins; */
  /*   ins.reg = REG_NONE; */
  /*   ins.op1 = record_stack_load(INS_B(i), frame); */
  /*   ins.op2 = record_stack_load(INS_C(i), frame); */
  /*   ins.op = IR_CLT; */
  /*   ins.type = 0; // TODO bool */
  /*   regs[reg] = arrlen(trace->ops); */
  /*   arrput(trace->ops, ins); */
  /*   break; */
  /* } */
  case JISF: {
    // TODO snaps
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc, depth);
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, FALSE_REP);
    ir_ins_op op;
    if (frame[INS_B(i)] == FALSE_REP) {
      op = IR_EQ;
    } else {
      op = IR_NE;
    }
    push_ir(trace, op, record_stack_load(INS_B(i), frame), knum | IR_CONST_BIAS, IR_INS_TYPE_GUARD);
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
    uint32_t op1  = record_stack_load(INS_B(i), frame);
    uint32_t op2  = record_stack_load(INS_C(i), frame);
    if (op1 >= IR_CONST_BIAS) {
      type = trace->consts[op1 - IR_CONST_BIAS] & TAG_MASK;
    } else {
      type = trace->ops[op1].type & ~IR_INS_TYPE_GUARD;
    }
    if (type != 0) {
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
    uint32_t op1  = record_stack_load(INS_B(i), frame);
    uint32_t op2  = record_stack_load(INS_C(i), frame);
    if (op1 >= IR_CONST_BIAS) {
      type = trace->consts[op1 - IR_CONST_BIAS] & TAG_MASK;
    } else {
      type = trace->ops[op1].type & ~IR_INS_TYPE_GUARD;
    }
    if (type != 0) {
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
  case UNBOX: // DO don't need typecheck
  case CDR:
  case CAR: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    ir_ins_op op;
    uint8_t type;
    if (INS_OP(i) == CAR || INS_OP(i) == UNBOX) {
      // TODO typecheck
      // TODO cleanup
      type = ((cons_s *)(frame[INS_B(i)] - CONS_TAG))->a & TAG_MASK;
      if (type == LITERAL_TAG) {
        type = ((cons_s *)(frame[INS_B(i)] - CONS_TAG))->a & IMMEDIATE_MASK;
      }
      op = IR_CAR;
    } else {
      type = ((cons_s *)(frame[INS_B(i)] - CONS_TAG))->b & TAG_MASK;
      if (type == LITERAL_TAG) {
        type = ((cons_s *)(frame[INS_B(i)] - CONS_TAG))->b & IMMEDIATE_MASK;
      }
      op = IR_CDR;
    }
    regs[INS_A(i)] = push_ir(trace, op, op1, IR_NONE, type | IR_INS_TYPE_GUARD);
    break;
  }
  case GUARD: {
    uint32_t op1 = record_stack_load(INS_B(i), frame);
    int64_t v = frame[INS_B(i)];
    auto type = INS_C(i);
    int64_t c = FALSE_REP;
    if ((type & TAG_MASK) == LITERAL_TAG) {
      if (type == (v & IMMEDIATE_MASK)) {
	c = TRUE_REP;
      }
    } else {
      if (type == (v & TAG_MASK)) {
	c = TRUE_REP;
      }
    }
    // TODO ptr
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, c);
    regs[INS_A(i)] = IR_CONST_BIAS + knum;
    break;
  }
  case JNGUARD: 
  case JGUARD: {
    record_stack_load(INS_B(i), frame);
    long tag = INS_C(i);

    if (tag == PTR_TAG) {
      // TODO should be checked by sload??
      assert(false);
    } else {
      // Nothing to do, SLOAD already checked.
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

    push_ir(trace, IR_ABC, vec, idx, 0);
    auto vref = push_ir(trace, IR_VREF, vec, idx, 0);
    push_ir(trace, IR_STORE, vref, obj, 0);

    // Record state because of IR_STORE
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);

    break;
  }
  case VECTOR_REF: {
    auto vec = record_stack_load(INS_B(i), frame);
    auto idx = record_stack_load(INS_C(i), frame);

    push_ir(trace, IR_ABC, vec, idx, 0);
    auto vref = push_ir(trace, IR_VREF, vec, idx, 0);

    uint64_t pos = frame[INS_C(i)] >> 3;
    vector_s* vec_d = (vector_s*)(frame[INS_B(i)] - PTR_TAG);
    uint8_t type = vec_d->v[pos] & TAG_MASK;
    if (type == LITERAL_TAG) {
      type = vec_d->v[pos] & IMMEDIATE_MASK;
    }
    regs[INS_A(i)] = push_ir(trace, IR_LOAD, vref, 0, IR_INS_TYPE_GUARD | type);

    break;
  }
  case STRING_REF: {
    auto str = record_stack_load(INS_B(i), frame);
    auto idx = record_stack_load(INS_C(i), frame);

    push_ir(trace, IR_ABC, str, idx, 0);
    regs[INS_A(i)] = push_ir(trace, IR_STRLD, str, idx, CHAR_TAG);

    break;
  }
  case STRING_SET: {
    auto str = record_stack_load(INS_A(i), frame);
    auto idx = record_stack_load(INS_B(i), frame);
    auto val = record_stack_load(INS_C(i), frame);

    push_ir(trace, IR_ABC, str, idx, 0);
    auto ref = push_ir(trace, IR_STRREF, str, idx, 0);
    push_ir(trace, IR_STRST, ref, val, 0);

    break;
  }
  case CLOSURE: {
    //add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc);
    //  TODO this forces a side exit without recording.
    //   Put GC inline in generated code?  Would have to flush
    //   all registers to stack.
    trace->snaps[arrlen(trace->snaps) - 1].exits = 100;
    // TODO fixed closz
    long closz = (frame[INS_A(i)+1] >> 3)+1;
    auto cell = push_ir(trace, IR_ALLOC, sizeof(long)* (closz + 2), CLOSURE_TAG, CLOSURE_TAG);
    auto ref = push_ir(trace, IR_REF, cell, 8 - CLOSURE_TAG, 0);
    auto knum = arrlen(trace->consts);
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
    for(long j = 0; j < closz; j++) {
      ref = push_ir(trace, IR_REF, cell, 16 +8*j - CLOSURE_TAG, 0);
      push_ir(trace, IR_STORE, ref, a, 0);
    }
    regs[INS_A(i)] = cell;
    /* for(unsigned j = 1; j < INS_B(i); j++) { */
    /*   regs[INS_A(i) + j] = -1; */
    /* } */
    //add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1);
    break;
  }
  case CONS: {
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc, depth);
    //  TODO this forces a side exit without recording.
    //   Put GC inline in generated code?  Would have to flush
    //   all registers to stack.
    trace->snaps[arrlen(trace->snaps) - 1].exits = 100; 
    auto a = record_stack_load(INS_B(i), frame);
    auto b = record_stack_load(INS_C(i), frame);
    auto cell = push_ir(trace, IR_ALLOC, sizeof(cons_s), CONS_TAG, CONS_TAG);
    regs[INS_A(i)] = cell;
    auto ref = push_ir(trace, IR_REF, cell, 8 - CONS_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, a, UNDEFINED_TAG);
    ref = push_ir(trace, IR_REF, cell, 8 + 8 - CONS_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, b, UNDEFINED_TAG);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);

    break;
  }
  case MOV: {
    regs[INS_A(i)] = record_stack_load(INS_B(i), frame);
    // TODO loop moves can clear
    // regs[INS_B(i)] = -1;
    break;
  }
  case READ: {
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, (long)vm_read_char);
    regs[INS_A(i)] = push_ir(trace, IR_CALLXS,
			     record_stack_load(INS_B(i), frame),
			     knum | IR_CONST_BIAS,
			     CHAR_TAG | IR_INS_TYPE_GUARD);
    add_snap(regs_list, (int)(regs - regs_list - 1), trace, pc + 1, depth);
    break;
  }
  case WRITE: {
    auto arg = push_ir(trace, IR_CARG, record_stack_load(INS_B(i), frame), record_stack_load(INS_C(i), frame), UNDEFINED_TAG);
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
    symbol *sym = (symbol*)(gp - SYMBOL_TAG);
    uint8_t type = sym->val & TAG_MASK;
    if (type == LITERAL_TAG) {
      type = sym->val & IMMEDIATE_MASK;
    }
    regs[INS_A(i)] = push_ir(trace, IR_GGET, knum | IR_CONST_BIAS, IR_NONE, type | IR_INS_TYPE_GUARD);
    break;
  }
  case GSET: {
    long gp = const_table[INS_D(i)];
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, gp);
    uint8_t type = (((symbol *)(gp - SYMBOL_TAG))->val & 0x7);
    push_ir(trace, IR_GSET, knum | IR_CONST_BIAS, record_stack_load(INS_A(i), frame), type);
    break;
  }
  case SUBVN: {
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, INS_C(i) << 3);
    auto op1 = record_stack_load(INS_B(i), frame);
    uint8_t type = 0;
    if (op1 >= IR_CONST_BIAS) {
      type = trace->consts[op1 - IR_CONST_BIAS] & TAG_MASK;
    } else {
      type = trace->ops[op1].type & ~IR_INS_TYPE_GUARD;
    }
    if (type != 0) {
      printf("Record abort: Only int supported in trace: %i\n", type);
      record_abort();
      return 1;
    }
    regs[INS_A(i)] = push_ir(trace, IR_SUB, op1, knum | IR_CONST_BIAS, IR_INS_TYPE_GUARD | type);
    break;
  }
  case ADDVN: {
    // TODO check type
    auto knum = arrlen(trace->consts);
    arrput(trace->consts, INS_C(i) << 3);
    auto op1 = record_stack_load(INS_B(i), frame);
    uint8_t type = 0;
    if (op1 >= IR_CONST_BIAS) {
      type = trace->consts[op1 - IR_CONST_BIAS] & TAG_MASK;
    } else {
      type = trace->ops[op1].type & ~IR_INS_TYPE_GUARD;
    }
    if (type != 0) {
      printf("Record abort: Only int supported in trace: %i\n", type);
      record_abort();
      return 1;
    }
    regs[INS_A(i)] = push_ir(trace, IR_ADD, op1, knum | IR_CONST_BIAS, type | IR_INS_TYPE_GUARD);
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
      printf("Record abort: Only int supported in trace: %i\n", type);
      record_abort();
      return 1;
    }
    regs[INS_A(i)] = push_ir(trace, IR_SUB, op1, op2, IR_INS_TYPE_GUARD | type);
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
    auto ref = push_ir(trace, IR_REF, clo, 16 + (8*(1 + INS_C(i))) - CLOSURE_TAG, UNDEFINED_TAG);
    
    // Note: Closure doesn't necessarily need typecheck since closures are CONST.
    // However, there are some situations where invalid code may hit bad types?
    // I.e. polymorphic functions could do a different STORE type?
    //
    // Actually, this is invalid: closures could close '() or a list, and still
    // be what code is expecting.
    uint64_t pos = INS_C(i) + 1;
    closure_s* clo_d = (closure_s*)(frame[INS_B(i)] - CLOSURE_TAG);
    uint8_t type = clo_d->v[pos] & TAG_MASK;
    if (type == LITERAL_TAG) {
      type = clo_d->v[pos] & IMMEDIATE_MASK;
    }

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
    auto ref = push_ir(trace, IR_REF, clo, 16 + (8*(1 + INS_C(i))) - CLOSURE_TAG, UNDEFINED_TAG);
    push_ir(trace, IR_STORE, ref, val, UNDEFINED_TAG);
    break;
  }
  case JMP: {
    break;
  }
  case JFUNC: {
    // Check if it is a returning trace
    auto *ctrace = trace_cache_get(INS_D(i));
    if (ctrace->link == -1) {
      assert(patchpc == nullptr);
      patchpc = pc;
      patchold = *pc;
      *pc = traces[INS_D(*pc)]->startpc;
      break;
    }
    for (int j = 0; j < INS_A(i); j++) {
      regs[j] = record_stack_load(j, frame);
    }
    printf("Record stop JFUNC\n");
    record_stop(pc, frame, INS_D(i));
    return 1;
  }
  case JLOOP: {
    if (side_exit == nullptr) {
      printf("Record abort: root trace hit loop\n");
      record_abort();
      return 1;
    }
    printf("Record stop hit JLOOP\n");
    // NOTE: stack load is for ret1 jloop returns.  Necessary?
    // TODO JLOOp also used for loop, only need to record for RET
    regs[INS_A(i)] = record_stack_load(INS_A(i), frame);
    record_stop(pc, frame, INS_D(i));
    return 1;
  }
  default: {
    bcfunc* fc = find_func_for_frame(pc);
    printf("Record abort: NYI: CANT RECORD BYTECODE %s in %s\n",
           ins_names[INS_OP(i)], fc->name);
    record_abort();
    return 1;
    // exit(-1);
  }
  }
  if (instr_count > 50) {
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
  if (depth >= 10) {
    printf("Record abort: (stack too deep)\n");
    record_abort();
    return 1;
  }
  return 0;
}

trace_s *trace_cache_get(unsigned int tnum) { return traces[tnum]; }

void free_trace() { printf("Traces: %li\n", arrlen(traces)); }
