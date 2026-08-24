#pragma once

#include "array.h"
#include "asm.h"
#include "assert.h"
#include "stdint.h"
#include "types.h"

typedef struct vm_state vm_state;

typedef struct {
  bool constant : 1;
  uint16_t loc : 15;
} slot;

typedef struct snap_entry {
  uint16_t slot;
  slot val;
} snap_entry;

typedef struct trace trace;
typedef struct {
  bc *pc;
  uint16_t ir;
  uint16_t offset;
  uint32_t argcnt;
  uint32_t mapofs;
  uint16_t nent;

  // Side trace info
  uint8_t depth;
  uint8_t exits;
  label patch_point;
  uint8_t **side_exit_jcc_locs;
  trace *trace;
} snap;

typedef enum : uint8_t {
  IR_ARG_NONE_NONE,
  IR_ARG_STACK,
  IR_ARG_IR_NONE,
  IR_ARG_IR_IR,
  IR_ARG_IR_ADDR,
  IR_ARG_REG,
  IR_ARG_PMOV,
  IR_ARG_OFFSET,
} ir_arg_type;

// Opname, arg types, side effecting
// VMCALLS *MUST* appear last, for regalloc and indexing.
// The comparison functions are also ordered! and inverted with ~
#define IR_OPS                                                                 \
  X(EQ, ARG_IR_IR, true)                                                       \
  X(NE, ARG_IR_IR, true)                                                       \
  X(LT, ARG_IR_IR, true)                                                       \
  X(GT, ARG_IR_IR, true)                                                       \
  X(LTE, ARG_IR_IR, true)                                                      \
  X(GTE, ARG_IR_IR, true)                                                      \
  X(ABC, ARG_IR_IR, true)                                                      \
  X(NOP, ARG_NONE_NONE, false)                                                 \
  X(CONST, ARG_IR_NONE, false)                                                 \
  X(ADD, ARG_IR_IR, false)                                                     \
  X(SUB, ARG_IR_IR, false)                                                     \
  X(MUL, ARG_IR_IR, false)                                                     \
  X(DIV, ARG_IR_IR, false)                                                     \
  X(QUOTIENT, ARG_IR_IR, false)                                                \
  X(MOD, ARG_IR_IR, false)                                                     \
  X(GGET, ARG_IR_NONE, false)                                                  \
  X(GSET, ARG_IR_IR, true)                                                     \
  X(RET, ARG_IR_ADDR, true)                                                    \
  X(STACK_STORE, ARG_IR_IR, true)                                              \
  X(STACK_LOAD_RAW, ARG_STACK, false)                                          \
  X(STACK_LEN_EQ, ARG_IR_IR, true)                                             \
  X(STACK_FITS_RESET, ARG_IR_NONE, true)                                       \
  X(STACK_RESET, ARG_NONE_NONE, true)                                          \
  X(STACK_SET_TOP, ARG_IR_NONE, true)                                          \
  X(SLOAD, ARG_STACK, false)                                                   \
  X(TYPECHECK, ARG_IR_NONE, true)                                              \
  X(PMOV, ARG_PMOV, false)                                                     \
  X(ARG, ARG_REG, false)                                                       \
  X(REF, ARG_IR_IR, false)                                                     \
  X(CARG, ARG_IR_IR, false)                                                    \
  X(CCALL, ARG_IR_IR, true)                                                    \
  X(LOAD, ARG_IR_IR, false)                                                    \
  X(LOAD_CHAR, ARG_IR_IR, false)                                               \
  X(LOAD_BYTE, ARG_IR_IR, false)                                               \
  X(FLVECTOR_REF, ARG_IR_IR, false)                                            \
  X(STORE, ARG_IR_IR, true)                                                    \
  X(STORE_CHAR, ARG_IR_IR, true)                                               \
  X(STORE_BYTE, ARG_IR_IR, true)                                               \
  X(FLVECTOR_SET, ARG_IR_IR, true)                                             \
  X(GCLOG, ARG_IR_IR, true)                                                    \
  X(ALLOC, ARG_IR_IR, false)                                                   \
  X(FLUSH, ARG_NONE_NONE, true)                                                \
  X(CALLCC, ARG_IR_IR, true)                                                   \
  X(CALLCC_RESUME, ARG_IR_NONE, true)                                          \
  X(BOX_FLONUM, ARG_IR_NONE, false)                                            \
  X(EXACT, ARG_IR_NONE, false)                                                 \
  X(INTEGER_CHAR, ARG_IR_NONE, false)                                          \
  X(CHAR_INTEGER, ARG_IR_NONE, false)                                          \
  X(TRUNCATE, ARG_IR_NONE, false)                                              \
  X(INEXACT, ARG_IR_NONE, false)                                               \
  X(VMADD, ARG_IR_IR, true)                                                    \
  X(VMSUB, ARG_IR_IR, true)                                                    \
  X(VMMUL, ARG_IR_IR, true)                                                    \
  X(VMDIV, ARG_IR_IR, true)                                                    \
  X(VMQUOTIENT, ARG_IR_IR, true)                                               \
  X(VMMOD, ARG_IR_IR, true)                                                    \
  X(VMMEMQ, ARG_IR_IR, true)                                                   \
  X(VMMEMV, ARG_IR_IR, true)                                                   \
  X(VMLT, ARG_IR_IR, true)                                                     \
  X(VMGT, ARG_IR_IR, true)                                                     \
  X(VMLTE, ARG_IR_IR, true)                                                    \
  X(VMGTE, ARG_IR_IR, true)                                                    \
  X(VMJEQV, ARG_IR_IR, true)                                                   \
  X(VMJNEQV, ARG_IR_IR, true)                                                  \
  X(VMJNUMEQ, ARG_IR_IR, true)                                                 \
  X(VMJNNUMEQ, ARG_IR_IR, true)                                                \
  X(VMINEXACT, ARG_IR_NONE, true)                                              \
  X(VMEXACT, ARG_IR_NONE, true)                                                \
  X(VMTRUNCATE, ARG_IR_NONE, true)                                             \
  X(SQRT, ARG_IR_NONE, false)
typedef enum : uint8_t {
#define X(name, type, sideeff) IR_##name,
  IR_OPS
#undef X
      IR_INS_MAX,
} ir_ins_op;

typedef struct {
  ir_ins_op op;
  uint8_t type : 7;
  uint8_t guard : 1;
  union {
    uint16_t prev;
    struct {
      uint8_t reg;
      uint16_t spill; // spill slot.
    };
  };
  union {
    struct {
      slot op1;
      slot op2;
    };
    // PMOV data
    struct {
      uint8_t prev_reg;
      bool prev_guard;
    };
    uint32_t data;
  };
} ir_ins;

static_assert(sizeof(ir_ins) == 12, "ir_ins instructions must be 12 bytes");

struct trace_result {
  gc_obj *stack;
  snap *snap;
};

typedef struct trace_result (*trace_fn)(vm_state *state, gc_obj *stack);
typedef enum : uint8_t {
  TRACE_ROOT,
  TRACE_SIDE,
  TRACE_POLY,
} trace_kind;

typedef struct trace {
  ir_ins *ins;
  gc_obj *consts;
  snap *snaps;
  snap_entry *snapmap;
  uint8_t **gc_const_locs;
  uint16_t cse_head[IR_INS_MAX];
  uint16_t *cse_prev;
  trace_fn fn;
  uint16_t num;
  trace_kind kind;
  bc *start_ins;
  snap *parent_snap;
  uint8_t link_entry_snap;
  trace *link;
  label trace_start;
  label snap_entry_label;
  bc start_pc;
  uint8_t *code_start;
  uint8_t *code_end;
  trace *next; // Chained polymorphic traces.
} trace;

static inline size_t snap_nent(snap const *sn) { return sn->nent; }

static inline snap_entry *snap_entries(trace *t, snap *sn) {
  assert(sn->mapofs + sn->nent <= arrlen(t->snapmap));
  if (!t->snapmap) {
    assert(sn->mapofs == 0 && sn->nent == 0);
    return nullptr;
  }
  return t->snapmap + sn->mapofs;
}

static inline snap_entry const *snap_entries_const(trace const *t,
                                                   snap const *sn) {
  assert(sn->mapofs + sn->nent <= arrlen(t->snapmap));
  if (!t->snapmap) {
    assert(sn->mapofs == 0 && sn->nent == 0);
    return nullptr;
  }
  return t->snapmap + sn->mapofs;
}

static inline bool ir_get_guard(trace *t, ir_ins *ins) {
  assert(ins->op == IR_TYPECHECK);

  assert(!ins->op1.constant);
  ir_ins *src = &t->ins[ins->op1.loc];
  // TYPECHECK guards mirror their source lazily, so record does not need to
  // scan forward from ARG/PMOV when an input later becomes guarded.
  if (src->guard) {
    ins->guard = true;
  }
  return ins->guard;
}

enum : uint16_t {
  SPILL_NONE = UINT16_MAX,
};

void print_ir(trace *t);

extern char *ir_names[];
extern ir_arg_type ir_ins_types[];

bool ir_sideeff(ir_ins_op op);
slot trace_add_const(trace *t, gc_obj value);
