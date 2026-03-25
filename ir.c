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
    } else if (is_cons(gc)) {
      printf("\e[1;31mCONS\e[m");
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
    printf("%04u", s.loc);
  }
}

static void print_ccall_sig(slot sig_slot, trace *t) {
  if (!sig_slot.constant) {
    print_slot(sig_slot, t);
    return;
  }

  auto sig_obj = t->consts[sig_slot.loc];
  if (!is_cons(sig_obj)) {
    print_slot(sig_slot, t);
    return;
  }
  auto sig_tail = to_cons(sig_obj)->b;
  if (!is_cons(sig_tail)) {
    print_slot(sig_slot, t);
    return;
  }
  auto name_obj = to_cons(sig_tail)->a;
  if (!is_string(name_obj)) {
    print_slot(sig_slot, t);
    return;
  }
  printf("\e[1;35m%s\e[m", to_string(name_obj)->str);
}

char *ir_names[] = {
#define X(name, type, sideeff) #name,
    IR_OPS
#undef X
};
ir_arg_type ir_ins_types[] = {
#define X(name, type, sideeff) IR_##type,
    IR_OPS
#undef X
};
static bool ir_has_side_effects[] = {
#define X(name, type, sideeff) sideeff,
    IR_OPS
#undef X
};

static void print_snap(snap *snap, trace *t, size_t snap_idx) {
  (void)snap_idx;
  printf("SNAP[ir=%i pc=%p off=%i argcnt=%i", snap->ir, snap->pc, snap->offset,
         snap->argcnt);
  uint64_t frame = snap->offset - 1;

  for (uint64_t j = arrlen(snap->slots); j != 0; j--) {
    auto entry = &snap->slots[j - 1];
    printf(" %02i=", entry->slot);
    if (entry->slot == frame) {
      printf("\e[1;34mframe\e[m");
      assert(entry->val.constant);
      uint8_t frame_offset =
          (to_return_address(t->consts[entry->val.loc]) - 1)->reg;
      frame -= (frame_offset + 1);
    } else if (!entry->val.constant) {
      printf("%04u", entry->val.loc);
      auto in = &t->ins[entry->val.loc];
      if (in->spill != SPILL_NONE) {
        printf(" (");
        printf("S%u", in->spill);
        printf(")");
      } else if (in->reg != REG_NONE) {
        printf(" (");
        printf("%s", reg_names[in->reg]);
        printf(")");
      }
    } else {
      print_slot(entry->val, t);
    }
  }
  printf("]\n");
}

void print_ir(trace *t) {
  uint64_t cur_snap = 0;
  for (size_t i = 0; i < arrlen(t->ins) + 1 /* last snap */; i++) {
    while (cur_snap < arrlen(t->snaps) && t->snaps[cur_snap].ir == i) {
      print_snap(&t->snaps[cur_snap], t, cur_snap);
      cur_snap++;
    }
    if (i == arrlen(t->ins)) {
      break;
    }
    ir_ins *ins = &t->ins[i];

    printf("%04zu", i);
    if (ins->reg != REG_NONE) {
      printf(" %-4s", reg_names[ins->reg]);
    } else {
      printf("     ");
    }
    if (ins->spill != SPILL_NONE) {
      printf("\e[1;31m[%i]\e[m ", ins->spill);
    } else {
      printf("    ");
    }
    printf("%s ", ins->guard ? ">" : " ");
    print_type_tag(stdout, ins->type);
    printf("%-8s", ir_names[ins->op]);
    ir_arg_type arg_type = ir_ins_types[ins->op];
    switch (arg_type) {
    case IR_ARG_NONE_NONE:
      break;
    case IR_ARG_STACK:
      printf(" \e[1;33mstack %i\e[m", ins->data);
      break;
    case IR_ARG_IR_NONE:
      printf(" ");
      print_slot(ins->op1, t);
      break;
    case IR_ARG_IR_IR:
      printf(" ");
      if (ins->op == IR_CCALL) {
        print_ccall_sig(ins->op1, t);
      } else {
        print_slot(ins->op1, t);
      }
      printf(", ");
      print_slot(ins->op2, t);
      break;
    case IR_ARG_IR_ADDR:
      printf(" ");
      print_slot(ins->op1, t);
      printf(", \e[1;35m#<bc 0x%" PRIx64 ">\e[m",
             (uint64_t)t->consts[ins->op2.loc].value);
      break;
    case IR_ARG_REG:
      printf(" \e[1;33m%i\e[m", ins->data);
      break;
    case IR_ARG_PMOV:
      printf(" %i %s (%s)", ins->prev_reg, ins->prev_guard ? "(GUARD)" : "",
             reg_names[ins->prev_reg]);
      break;
    case IR_ARG_OFFSET:
      printf(" +%i", ins->data);
      break;
    }
    printf("\n");
  }
}

bool ir_sideeff(ir_ins_op op) { return ir_has_side_effects[op]; }
