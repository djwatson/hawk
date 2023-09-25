#include "trace_dump.h"
#include "ir.h"
#include "types.h"
#include "asm_x64.h"  // for REG_NONE, asm_jit, reg_names
#include "third-party/stb_ds.h"

#include <stdbool.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define auto __auto_type
#define nullptr NULL

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
      auto type2 = ((long*)(c - PTR_TAG))[0] & 0xff;
      if (type2 == VECTOR_TAG) {
	printf("vector");
      } else  if (type2 == STRING_TAG) {
	printf("str");
      } else  if (type2 == PORT_TAG) {
	printf("port");
      } else {
	printf("ptr");
      }
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
    case IR_GCLOG:
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

