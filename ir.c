#include "ir.h"

static void print_slot(slot s, trace *t) {
  if (s.constant) {
    auto gc = t->consts[s.loc];
    if (is_fixnum(gc)) {
      printf("\e[1;35m%li\e[m", to_fixnum(gc));
    } else if (is_char(gc)) {
      printf("\e[1;35m'%c'\e[m", to_char(gc));
    } else if (is_string(gc)) {
      printf("\e[1;35m\"%s\"\e[m", to_string(gc)->str);
    } else if (is_record(gc)) {
      printf("\e[1;35m#<record>\e[m");
    } else if (is_flonum(gc)) {
      printf("\e[1;35m%f\e[m", to_flonum(gc)->x);
    } else if (is_symbol(gc)) {
      auto name = get_sym_name(to_symbol(gc));
      printf("\e[1;35m%s\e[m", name ? name->str : "<symbol>");
    } else if (gc.value == FALSE_REP.value) {
      printf("\e[1;35m#f\e[m");
    } else if (gc.value == TRUE_REP.value) {
      printf("\e[1;35m#t\e[m");
    } else if (is_closure(gc)) {
      printf("\e[1;31mCLOSURE\e[m");
    } else if (is_vector(gc)) {
      printf("\e[1;31mvector\e[m");
    } else if (is_func(gc)) {
      printf("\e[1;31mFUNC\e[m");
    } else if (gc.value == NIL.value) {
      printf("\e[1;35m()\e[m");
    } else {
      printf("\e[1;31mUNKNOWN %lx\e[m", gc.value);
    }
  } else {
    printf("%04d", s.loc);
  }
}

static void print_slot_immediate(slot s) {
  if (s.constant) {
    printf("\e[1;33m#%i\e[m", s.loc);
  } else {
    printf("v%u", (unsigned)s.loc);
  }
}

char *ir_names[] = {
#define X(name) #name,
    IR_OPS
#undef X
};

void print_ir(trace *t) {
  size_t count = arrlen_ins(t->ins);
  for (size_t i = 0; i < count; i++) {
    ir_ins *ins = &t->ins[i];
    printf("%04zu %-8s", i, ir_names[ins->op]);
    switch (ins->op) {
    case IR_NOP:
      break;
    case IR_SLOAD:
      printf(" \e[1;33mstack %i\e[m", ins->data);
      break;
    case IR_GGET:
    case IR_ARG:
      printf(" ");
      print_slot(ins->op1, t);
      break;
    case IR_REF:
      printf(" ");
      print_slot(ins->op1, t);
      printf(", ");
      print_slot_immediate(ins->op2);
      break;
    case IR_LOAD:
      printf(" ");
      print_slot(ins->op1, t);
      printf(", ");
      print_slot_immediate(ins->op2);
      break;
    case IR_GSET:
    case IR_ADD:
    case IR_SUB:
    case IR_LT:
    case IR_GUARD_EQ:
    case IR_STORE:
      printf(" ");
      print_slot(ins->op1, t);
      printf(", ");
      print_slot(ins->op2, t);
      break;
    case IR_RET:
      printf(" ");
      print_slot(ins->op1, t);
      if (ins->op2.constant || ins->op2.loc) {
        printf(", ");
        print_slot(ins->op2, t);
      }
      break;
    default:
      if (ins->data) {
        printf(" data=%u", ins->data);
      }
      break;
    }
    if (ins->reg != REG_NONE) {
      printf(" ; r%u", ins->reg);
    }
    if (ins->spill != SPILL_NONE) {
      printf(" ; spill%u", ins->spill);
    }
    printf("\n");
  }
}
