#include "ir.h"

static void print_const(gc_obj obj) {
  uint64_t raw = (uint64_t)obj.value;
  uint8_t low_tag = raw & TAG_MASK;
  if (raw == (uint64_t)TRUE_REP.value) {
    printf("#t");
    return;
  }
  if (raw == (uint64_t)FALSE_REP.value) {
    printf("#f");
    return;
  }
  if ((raw & IMMEDIATE_MASK) == NIL_TAG) {
    printf("nil");
    return;
  }
  if ((raw & IMMEDIATE_MASK) == EOF_TAG) {
    printf("eof");
    return;
  }
  if ((raw & IMMEDIATE_MASK) == CHAR_TAG) {
    printf("'%c'", to_char(obj));
    return;
  }
  if (low_tag == FIXNUM_TAG) {
    printf("%lld", (long long)to_fixnum(obj));
    return;
  }
  printf("0x%llx", (unsigned long long)raw);
}

static void print_slot_value(slot s, trace *t) {
  if (s.constant) {
    printf("k%u", (unsigned)s.loc);
    size_t const_count = arrlen_consts(t->consts);
    if (s.loc < const_count) {
      printf("=");
      print_const(t->consts[s.loc]);
    }
  } else {
    printf("v%u", (unsigned)s.loc);
  }
}

static void print_slot_immediate(slot s) {
  if (s.constant) {
    printf("#%u", (unsigned)s.loc);
  } else {
    printf("v%u", (unsigned)s.loc);
  }
}

char *ir_names[] = {
#define X(name) #name,
  IR_OPS
  #undef X
};

void print_ir(trace* t) {
  size_t count = arrlen_ins(t->ins);
  for (size_t i = 0; i < count; i++) {
    ir_ins* ins = &t->ins[i];
    printf("%04zu %-8s", i, ir_names[ins->op]);
    switch (ins->op) {
    case IR_NOP:
      break;
    case IR_SLOAD:
      printf(" stack[%u]", ins->data);
      break;
    case IR_GGET:
    case IR_ARG:
      printf(" ");
      print_slot_value(ins->op1, t);
      break;
    case IR_REF:
      printf(" ");
      print_slot_value(ins->op1, t);
      printf(", ");
      print_slot_immediate(ins->op2);
      break;
    case IR_LOAD:
      printf(" ");
      print_slot_value(ins->op1, t);
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
      print_slot_value(ins->op1, t);
      printf(", ");
      print_slot_value(ins->op2, t);
      break;
    case IR_RET:
      printf(" ");
      print_slot_value(ins->op1, t);
      if (ins->op2.constant || ins->op2.loc) {
        printf(", ");
        print_slot_value(ins->op2, t);
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
