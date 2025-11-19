#include "ir.h"
#include "asm.h"

#include <assert.h>
#include <inttypes.h>

static void print_slot(slot s, trace *t) {
  if (s.constant) {
    auto gc = t->consts[s.loc];
    if (is_fixnum(gc)) {
      printf("\e[1;35m%" PRId64 "\e[m", to_fixnum(gc));
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
      printf("\e[1;31mUNKNOWN %" PRIx64 "\e[m", (uint64_t)gc.value);
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
#define X(name, type) #name,
    IR_OPS
#undef X
};
ir_arg_type ir_ins_types[] = {
#define X(name, type) IR_##type,
    IR_OPS
#undef X
};

static void print_snap(snap *snap, trace *t) {
  printf("SNAP[ir=%i pc=%p off=%i", snap->ir, snap->pc, snap->offset);
  uint64_t frame = snap->offset - 1;
  for (uint64_t j = arrlen(snap->slots); j != 0; j--) {
    auto entry = &snap->slots[j - 1];
    printf(" %i=", entry->slot);
    if (entry->slot == frame) {
      printf("\e[1;34mframe\e[m");
      assert(entry->val.constant);
      uint8_t frame_offset =
          (to_return_address(t->consts[entry->val.loc]) - 1)->reg;
      frame -= (frame_offset + 1);
    } else {
      print_slot(entry->val, t);
    }
  }
  printf("]\n");
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
  case CONT_TAG:
    printf("\e[1;34mcont\e[m ");
    break;
  case PTR_TAG:
    printf("\e[1;34mptr \e[m ");
    break;
  case CHAR_TAG:
    printf("\e[1;34mchar\e[m ");
    break;
  case CLOSURE_TAG:
    printf("\e[1;34mclo \e[m ");
    break;
  default:
    // Also UNDEFINED_TAG
    printf("     ");
    break;
  }
}

void print_ir(trace *t) {
  uint64_t cur_snap = 0;
  for (size_t i = 0; i < arrlen(t->ins) + 1 /* last snap */; i++) {
    while (cur_snap < arrlen(t->snaps) && t->snaps[cur_snap].ir == i) {
      print_snap(&t->snaps[cur_snap], t);
      cur_snap++;
    }
    if (i == arrlen(t->ins)) {
      break;
    }
    ir_ins *ins = &t->ins[i];
    printf("%04zu", i);
    if (ins->reg != REG_NONE) {
      if (ins->type == FLONUM_TAG) {
        printf(" %-4s", freg_names[ins->reg]);
      } else {
        printf(" %-4s", reg_names[ins->reg]);
      }
    } else {
      printf("     ");
    }
    if (ins->spill != SPILL_NONE) {
      printf("\e[1;31m[%i]\e[m ", ins->spill);
    } else {
      printf("    ");
    }
    printf("%s ", ins->guard ? ">" : " ");
    print_tag_type(ins->type);
    printf("%-8s", ir_names[ins->op]);
    switch (ins->op) {
    case IR_NOP:
      break;
    case IR_SLOAD:
      printf(" \e[1;33mstack %i\e[m", ins->data);
      break;
    case IR_GGET:
      printf(" ");
      print_slot(ins->op1, t);
      break;
    case IR_REF:
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
    case IR_EQ:
    case IR_NE:
    case IR_GT:
    case IR_GTE:
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
      printf(", \e[1;35m#<bc 0x%" PRIx64 ">\e[m",
             (uint64_t)t->consts[ins->op2.loc].value);
      break;
    case IR_PMOV:
      printf(" %i (%s)", ins->data, reg_names[ins->data]);
      break;
    case IR_ARG:
      printf(" \e[1;33m%i\e[m", ins->data);
      break;
    default:
      if (ins->data) {
        printf(" data=%u", ins->data);
      }
      break;
    }
    printf("\n");
  }
}

bool ir_sideeff(ir_ins_op op) {
  switch (op) {
  case IR_GSET:
  case IR_RET:
  case IR_GT:
  case IR_LT:
  case IR_LTE:
  case IR_GTE:
  case IR_EQ:
  case IR_NE:
  case IR_GUARD_EQ:
  case IR_LOAD:
  case IR_PMOV:
    return true;
    break;
  default:
    return false;
  }
}
