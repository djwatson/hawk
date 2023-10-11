// Copyright 2023 Dave Watson

#include "trace_dump.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "asm_x64.h" // for REG_NONE, asm_jit, reg_names
#include "defs.h"
#include "ir.h"
#include "third-party/stb_ds.h"
#include "types.h"

static void print_literal(gc_obj c) {
  if (c == FALSE_REP) {
    printf("\e[1;35m#f\e[m");
  } else if (c == TRUE_REP) {
    printf("\e[1;35m#t\e[m");
  } else if (c == NIL_TAG) {
    printf("\e[1;35mnil\e[m");
  } else if (get_imm_tag(c) == CHAR_TAG) {
    printf("'%c'", to_char(c));
  } else if (c == EOF_TAG) {
    printf("eof");
  } else {
    printf("frame");
  }
}

static void print_const_or_val(int i, trace_s *ctrace) {
  if (ir_is_const(i)) {
    gc_obj c = ctrace->consts[i - IR_CONST_BIAS];
    int type = get_tag(c);
    switch (type) {
    case FIXNUM_TAG:
      printf("\e[1;35m%li\e[m", c >> 3);
      break;
    case CLOSURE_TAG:
      printf("\e[1;31m<closure>\e[m");
      break;
    case LITERAL_TAG:
      print_literal(c);
      break;
    case CONS_TAG:
      printf("\e[1;35mcons\e[m");
      break;
    case FLONUM_TAG:
      printf("\e[1;35m%f\e[m", to_flonum(c)->x);
      break;
    case VECTOR_TAG:
      printf("#(...)");
      break;
    case SYMBOL_TAG: {
      string_s *sym_name = get_sym_name(to_symbol(c));
      printf("\e[1;35m%s\e[m", sym_name->str);
      break;
    }
    case PTR_TAG: {
      auto type2 = get_ptr_tag(c);
      if (type2 == STRING_TAG) {
        printf("str");
      } else if (type2 == PORT_TAG) {
        printf("port");
      } else {
        printf("ptr");
      }
      break;
    }
    default:
      printf("Unknown print_const_or_val type: %i\n", type);
      break;
    }
  } else {
    printf("%04d", i);
  }
}

static void print_tag_type(uint8_t t) {
  switch (t) {
  case FIXNUM_TAG:
    printf("\e[1;35mfix \e[m ");
    break;
  case CONS_TAG:
    printf("\e[1;34mcons\e[m ");
    break;
  case FLONUM_TAG:
    printf("\e[1;34mflo \e[m ");
    break;
  case SYMBOL_TAG:
    printf("\e[1;34msym \e[m ");
    break;
  case BOOL_TAG:
    printf("\e[1;34mbool\e[m ");
    break;
  case NIL_TAG:
    printf("\e[1;34mnil \e[m ");
    break;
  case EOF_TAG:
    printf("\e[1;34meof \e[m ");
    break;
  case STRING_TAG:
    printf("\e[1;34mstr \e[m ");
    break;
  case VECTOR_TAG:
    printf("\e[1;34mvec \e[m ");
    break;
  case PORT_TAG:
    printf("\e[1;34mport\e[m ");
    break;
  case CONT_TAG:
    printf("\e[1;34mcont\e[m ");
    break;
  case PTR_TAG:
    printf("\e[1;34mptr \e[m ");
    break;
  case CHAR_TAG:
    printf("\e[1;34mchar\e[m ");
    break;
  default:
    // Also UNDEFINED_TAG
    printf("     ");
    break;
  }
}

static void print_ir(ir_ins op, trace_s *ctrace) {
  printf("%s ", ir_names[op.op]);
  switch (ir_ins_arg_type[op.op]) {
  case IR_ARG_NONE_NONE:
    break;
  case IR_ARG_IR_NONE:
    print_const_or_val(op.op1, ctrace);
    break;
  case IR_ARG_SYM_NONE: {
    auto s = to_symbol(ctrace->consts[op.op1 - IR_CONST_BIAS]);
    string_s *sym_name = get_sym_name(s);
    printf("%s", sym_name->str);
    break;
  }
  case IR_ARG_SYM_IR: {
    auto s = to_symbol(ctrace->consts[op.op1 - IR_CONST_BIAS]);
    string_s *sym_name = get_sym_name(s);
    printf("%s ", sym_name->str);
    print_const_or_val(op.op2, ctrace);
    break;
  }
  case IR_ARG_IR_TYPE:
    print_const_or_val(op.op1, ctrace);
    printf(" type %i", op.op2);
    break;
  case IR_ARG_IR_IR:
    print_const_or_val(op.op1, ctrace);
    printf(" ");
    print_const_or_val(op.op2, ctrace);
    break;
  case IR_ARG_IR_OFFSET:
    print_const_or_val(op.op1, ctrace);
    printf(" offset %i", op.op2);
    break;
  }
}

void dump_trace(trace_s *ctrace) {
  uint64_t cur_snap = 0;
  for (size_t i = 0; i < arrlen(ctrace->ops) + 1 /* extra snap */; i++) {
    // Print any snap
    while ((cur_snap < arrlen(ctrace->snaps)) &&
           ctrace->snaps[cur_snap].ir == i) {
      auto snap = &ctrace->snaps[cur_snap];
      printf("SNAP[ir=%i pc=%p off=%i", snap->ir, snap->pc, snap->offset);
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

    if (op.slot == SLOT_NONE) {
      printf("    ");
    } else {
      printf("\e[1;31m[%i]\e[m ", op.slot);
    }
    printf("%c\t", is_type_guard(op.type) ? '>' : ' ');
    auto t = get_type(op.type);
    print_tag_type(t);
    print_ir(op, ctrace);
    printf("\n");
  }
}
