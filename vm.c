// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#include "stdint.h"

typedef enum {
  OP_ADD,
  OP_SUB,
  OP_CONST,
  OP_RET,
  OP_LOOKUP,
  OP_FUNC,
  OP_LT,
  OP_IF,
  OP_CLOSURE_GET,
  OP_LCALL,
  OP_HALT,
} ops;

typedef struct {
  union {
    struct {
      ops op;
      uint8_t reg;
      union {
        struct {
          uint8_t v1;
          uint8_t v2;
        };
        uint16_t data;
      };
    };
    uint32_t full_data;
  };
} bc;

typedef struct {
  union {
    int64_t value;
    bc *raddress;
    void *ptr;
  };
} gc_obj;

static bc prog_fib_code[] = {
    {.op = OP_FUNC, .reg = 2, .v1 = 0, .v2 = 0},   // FUNC           2
    {.op = OP_CONST, .reg = 2, .v1 = 0, .v2 = 0},  // CONST          2 0
    {.op = OP_LT, .reg = 2, .v1 = 1, .v2 = 2},     // FX_LT          2 1 2
    {.op = OP_IF, .reg = 0, .v1 = 2, .v2 = 2},     // IF             2 2  ==> 6
    {.op = OP_RET, .reg = 1, .v1 = 0, .v2 = 0},    // RET            1
    {.op = OP_LOOKUP, .reg = 3, .v1 = 1, .v2 = 0}, // LOOKUP         3 1
    {.op = OP_CONST, .reg = 4, .v1 = 2, .v2 = 0},  // CONST          4 2
    {.op = OP_SUB, .reg = 4, .v1 = 1, .v2 = 4},    // SUB            4 1 4
    {.op = OP_CONST, .reg = 2, .v1 = 3, .v2 = 0},  // CONST          2 3
    {.op = OP_CLOSURE_GET, .reg = 2, .v1 = 3, .v2 = 2}, // CLOSURE_GET    2 3 2
    {.op = OP_LCALL, .reg = 2, .v1 = 3, .v2 = 0},       // LCALL          2 3
    {.op = OP_LOOKUP, .reg = 4, .v1 = 1, .v2 = 0},      // LOOKUP         4 1
    {.op = OP_CONST, .reg = 5, .v1 = 0, .v2 = 0},       // CONST          5 0
    {.op = OP_SUB, .reg = 5, .v1 = 1, .v2 = 5},         // SUB            5 1 5
    {.op = OP_CONST, .reg = 3, .v1 = 3, .v2 = 0},       // CONST          3 3
    {.op = OP_CLOSURE_GET, .reg = 3, .v1 = 4, .v2 = 3}, // CLOSURE_GET    3 4 3
    {.op = OP_LCALL, .reg = 3, .v1 = 3, .v2 = 0},       // LCALL          3 3
    {.op = OP_ADD, .reg = 2, .v1 = 2, .v2 = 3},         // ADD            2 2 3
    {.op = OP_RET, .reg = 2, .v1 = 0, .v2 = 0},         // RET            2
    {.op = OP_HALT, .reg = 0, .v1 = 0, .v2 = 0},        // HALT
};

gc_obj stack_load(uint8_t slot);
gc_obj const_load(uint16_t offset);
#define emit_ov_math_op(name, sym, v1, v2) stack_load(v1);
#define emit_math_cmp(name, sym, v1, v2) stack_load(v1);
#define ensure_type(type, val)
void return_frame(void *pc);
gc_obj sym_load(gc_obj sym);
void prepare_call(gc_obj fun);
void check_arity(gc_obj fun, gc_obj args);
void call_dispatch(gc_obj fun);
void stack_save(uint8_t slot, gc_obj res);
void branch_if_false(gc_obj b);
gc_obj closure_get(gc_obj clo, uint8_t slot);
gc_obj return_address(bc *);
void adjust_stack_depth(int depth);
void set_new_pc(bc *func);
void halt();

int vm(bc *pc) {
  while (true) {
    switch (pc->op) {
#include "vmgen.c"
    };
  }
}
