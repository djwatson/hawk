#include "ir.h"
#include "asm.h"
#include "regalloc.h"

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

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

static void print_alloc_loc(dense_loc_entry d) {
  if (d.kind == LOC_REG) {
    printf("%s", reg_names[d.reg]);
  } else {
    printf("S%u", d.spill);
  }
}

static size_t ir_dense_row_end(trace const *t, regalloc2_result const *r,
                               size_t ir_idx) {
  size_t ins_len = arrlen(t->ins);
  size_t snap_len = arrlen(t->snaps);
  if (ir_idx + 1 < ins_len) {
    return r->ir_id_to_dense_map[ir_idx + 1];
  }
  if (snap_len > 0) {
    return r->snap_id_to_dense_map[0];
  }
  return r->dense_locs ? arrlen(r->dense_locs) : 0;
}

static size_t snap_dense_row_end(trace const *t, regalloc2_result const *r,
                                 size_t snap_idx) {
  size_t snap_len = arrlen(t->snaps);
  if (snap_idx + 1 < snap_len) {
    return r->snap_id_to_dense_map[snap_idx + 1];
  }
  return r->dense_locs ? arrlen(r->dense_locs) : 0;
}

static void print_input_slot(slot s, trace *t, dense_loc_entry const *in_loc) {
  if (s.constant) {
    print_slot(s, t);
    return;
  }
  printf("%04u", s.loc);
  if (in_loc) {
    printf(" (");
    print_alloc_loc(*in_loc);
    printf(")");
  }
}

static void print_spill_reload_events(regalloc2_result const *regmap, size_t ir,
                                      bool before) {
  arr_for_each_idx(regmap->spill_reload_ops, eidx) {
    auto e = regmap->spill_reload_ops[eidx];
    if (e.ir_idx == ir && e.before == before) {
      printf("    %s %s ir=%zu v%u reg=%s spill=%u\n",
             e.is_reload ? "RELOAD" : "SPILL", before ? "BEFORE" : "AFTER ",
             ir, e.value_id, reg_names[e.reg], e.spill);
    }
  }
}

static void print_snap(snap *snap, trace *t, regalloc2_result const *regmap,
                       size_t snap_idx) {
  printf("SNAP[ir=%i pc=%p off=%i", snap->ir, snap->pc, snap->offset);
  uint64_t frame = snap->offset - 1;
  size_t sstart = 0;
  size_t send = 0;
  size_t dense_cur = 0;
  size_t *dense_by_entry = NULL;
  if (regmap) {
    sstart = regmap->snap_id_to_dense_map[snap_idx];
    send = snap_dense_row_end(t, regmap, snap_idx);
    size_t entry_len = arrlen(snap->slots);
    dense_by_entry = calloc(entry_len, sizeof(size_t));
    assert(dense_by_entry != NULL || entry_len == 0);
    for (size_t i = 0; i < entry_len; i++) {
      dense_by_entry[i] = SIZE_MAX;
    }
    dense_cur = sstart;
    arr_for_each_idx(snap->slots, k) {
      auto e = snap->slots[k];
      if (!e.val.constant && dense_cur < send) {
        dense_by_entry[k] = dense_cur++;
      }
    }
  }

  for (uint64_t j = arrlen(snap->slots); j != 0; j--) {
    auto entry = &snap->slots[j - 1];
    printf(" %02i=", entry->slot);
    if (entry->slot == frame) {
      printf("\e[1;34mframe\e[m");
      assert(entry->val.constant);
      uint8_t frame_offset =
          (to_return_address(t->consts[entry->val.loc]) - 1)->reg;
      frame -= (frame_offset + 1);
    } else if (regmap && !entry->val.constant) {
      printf("%04u", entry->val.loc);
      if (dense_by_entry[j - 1] != SIZE_MAX) {
        printf(" (");
        print_alloc_loc(regmap->dense_locs[dense_by_entry[j - 1]]);
        printf(")");
      }
    } else {
      print_slot(entry->val, t);
    }
  }
  free(dense_by_entry);
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
  case FUNC_TAG:
    printf("\e[1;34mfunc\e[m ");
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

void print_ir(trace *t, regalloc2_result const *regmap) {
  uint64_t cur_snap = 0;
  for (size_t i = 0; i < arrlen(t->ins) + 1 /* last snap */; i++) {
    while (cur_snap < arrlen(t->snaps) && t->snaps[cur_snap].ir == i) {
      print_snap(&t->snaps[cur_snap], t, regmap, cur_snap);
      cur_snap++;
    }
    if (i == arrlen(t->ins)) {
      break;
    }
    if (regmap) {
      print_spill_reload_events(regmap, i, true);
    }
    ir_ins *ins = &t->ins[i];
    size_t in_idx = 0;
    size_t end = 0;
    if (regmap) {
      in_idx = regmap->ir_id_to_dense_map[i];
      end = ir_dense_row_end(t, regmap, i);
    }

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
    print_tag_type(ins->type);
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
      if (regmap) {
        print_input_slot(ins->op1, t, ins->op1.constant || in_idx >= end
                                         ? NULL
                                         : &regmap->dense_locs[in_idx++]);
      } else {
        print_slot(ins->op1, t);
      }
      break;
    case IR_ARG_IR_IR:
      printf(" ");
      if (regmap) {
        print_input_slot(ins->op1, t, ins->op1.constant || in_idx >= end
                                         ? NULL
                                         : &regmap->dense_locs[in_idx++]);
      } else {
        print_slot(ins->op1, t);
      }
      printf(", ");
      if (regmap) {
        print_input_slot(ins->op2, t, ins->op2.constant || in_idx >= end
                                         ? NULL
                                         : &regmap->dense_locs[in_idx++]);
      } else {
        print_slot(ins->op2, t);
      }
      break;
    case IR_ARG_IR_ADDR:
      printf(" ");
      if (regmap) {
        print_input_slot(ins->op1, t, ins->op1.constant || in_idx >= end
                                         ? NULL
                                         : &regmap->dense_locs[in_idx++]);
      } else {
        print_slot(ins->op1, t);
      }
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
    if (regmap) {
      print_spill_reload_events(regmap, i, false);
    }
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
  case IR_STORE:
  case IR_PMOV:
  case IR_ALLOC:
  case IR_TYPECHECK:
    return true;
    break;
  default:
    return false;
  }
}
