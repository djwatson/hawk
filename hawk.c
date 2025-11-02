#include "hawk.h"
#include "bc.h"
#include "types.h"

BCFUNC_FLEXARRAY_DIAG_PUSH
typedef struct {
  bcfunc func;
  gc_obj consts[4];
  bc code[20];
} prog_fib_bc;
BCFUNC_FLEXARRAY_DIAG_POP

static symbol fib_sym;
static prog_fib_bc prog_fib = {
    .func =
        {
            .const_cnt = 4,
            .bc_cnt = 20,
        },
    .consts =
        {
            tag_fixnum(2),
            tag_symbol(&fib_sym),
            tag_fixnum(1),
            tag_fixnum(-1),
        },
    .code =
        {
            {OP_FUNC, 2, 0, 0},        // FUNC           2
            {OP_CONST, 2, 0, 0},       // CONST          2 0
            {OP_LT, 2, 1, 2},          // FX_LT          2 1 2
            {OP_IF, 0, 2, 2},          // IF             2 2  ==> 6
            {OP_RET, 1, 0, 0},         // RET            1
            {OP_LOOKUP, 3, 1, 0},      // LOOKUP         3 1
            {OP_CONST, 4, 2, 0},       // CONST          4 2
            {OP_SUB, 4, 1, 4},         // SUB            4 1 4
            {OP_CONST, 2, 3, 0},       // CONST          2 3
            {OP_CLOSURE_GET, 2, 3, 2}, // CLOSURE_GET    2 3 2
            {OP_LCALL, 2, 3, 0},       // LCALL          2 3
            {OP_LOOKUP, 4, 1, 0},      // LOOKUP         4 1
            {OP_CONST, 5, 0, 0},       // CONST          5 0
            {OP_SUB, 5, 1, 5},         // SUB            5 1 5
            {OP_CONST, 3, 3, 0},       // CONST          3 3
            {OP_CLOSURE_GET, 3, 4, 3}, // CLOSURE_GET    3 4 3
            {OP_LCALL, 3, 3, 0},       // LCALL          3 3
            {OP_ADD, 2, 2, 3},         // ADD            2 2 3
            {OP_RET, 2, 0, 0},         // RET            2
            {OP_HALT, 0, 0, 0},        // HALT
        },
};

static closure_s fib_clo = {.header =
                                {
                                    .type = CLOSURE_TAG,
                                },
                            .len = tag_fixnum(1),
                            .v = {tag_func(&prog_fib)}};
static symbol fib_sym = {
    .header =
        {
            .type = SYMBOL_TAG,
        },

    .val = tag_closure(&fib_clo),
};

BCFUNC_FLEXARRAY_DIAG_PUSH
typedef struct {
  bcfunc func;
  gc_obj consts[2];
  bc code[4];
} fib_loader_bc;
BCFUNC_FLEXARRAY_DIAG_POP

static fib_loader_bc fib_loader = {
    .func =
        {
            .const_cnt = 2,
            .bc_cnt = 4,
        },
    .consts =
        {
            {.raddress = prog_fib.code}, // entry to PROG-fib
            tag_fixnum(40),
        },
    .code =
        {
            {OP_CONST, 2, 0, 0}, // load fib entry
            {OP_CONST, 1, 1, 0}, // push argument 40
            {OP_LCALL, 2, 0, 0}, // invoke fib
            {OP_HALT, 0, 0, 0},  // halt after call
        },
};

int main() {}
