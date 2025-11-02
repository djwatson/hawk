#include "bc.h"
#include "types.h"

typedef struct {
  bcfunc func;
  gc_obj consts[4];
  bc code[20];
} prog_fib_bc;

static prog_fib_bc prog_fib = {
    .func =
        {
            .const_cnt = 4,
            .bc_cnt = 20,
        },
    .consts =
        {
            {.value = 2},
            {.ptr = nullptr}, // PROG-fib symbol wired in later
            {.value = 1},
            {.value = -1},
        },
    .code =
        {
            {.op = OP_FUNC, .reg = 2, .v1 = 0, .v2 = 0},  // FUNC           2
            {.op = OP_CONST, .reg = 2, .v1 = 0, .v2 = 0}, // CONST          2 0
            {.op = OP_LT, .reg = 2, .v1 = 1, .v2 = 2}, // FX_LT          2 1 2
            {.op = OP_IF,
             .reg = 0,
             .v1 = 2,
             .v2 = 2}, // IF             2 2  ==> 6
            {.op = OP_RET, .reg = 1, .v1 = 0, .v2 = 0},    // RET            1
            {.op = OP_LOOKUP, .reg = 3, .v1 = 1, .v2 = 0}, // LOOKUP         3 1
            {.op = OP_CONST, .reg = 4, .v1 = 2, .v2 = 0},  // CONST          4 2
            {.op = OP_SUB, .reg = 4, .v1 = 1, .v2 = 4}, // SUB            4 1 4
            {.op = OP_CONST, .reg = 2, .v1 = 3, .v2 = 0}, // CONST          2 3
            {.op = OP_CLOSURE_GET,
             .reg = 2,
             .v1 = 3,
             .v2 = 2}, // CLOSURE_GET    2 3 2
            {.op = OP_LCALL, .reg = 2, .v1 = 3, .v2 = 0},  // LCALL          2 3
            {.op = OP_LOOKUP, .reg = 4, .v1 = 1, .v2 = 0}, // LOOKUP         4 1
            {.op = OP_CONST, .reg = 5, .v1 = 0, .v2 = 0},  // CONST          5 0
            {.op = OP_SUB, .reg = 5, .v1 = 1, .v2 = 5}, // SUB            5 1 5
            {.op = OP_CONST, .reg = 3, .v1 = 3, .v2 = 0}, // CONST          3 3
            {.op = OP_CLOSURE_GET,
             .reg = 3,
             .v1 = 4,
             .v2 = 3}, // CLOSURE_GET    3 4 3
            {.op = OP_LCALL, .reg = 3, .v1 = 3, .v2 = 0}, // LCALL          3 3
            {.op = OP_ADD, .reg = 2, .v1 = 2, .v2 = 3},  // ADD            2 2 3
            {.op = OP_RET, .reg = 2, .v1 = 0, .v2 = 0},  // RET            2
            {.op = OP_HALT, .reg = 0, .v1 = 0, .v2 = 0}, // HALT
        },
};

typedef struct {
  bcfunc func;
  gc_obj consts[2];
  bc code[4];
} fib_loader_bc;

static fib_loader_bc fib_loader = {
    .func =
        {
            .const_cnt = 2,
            .bc_cnt = 4,
        },
    .consts =
        {
            {.raddress = prog_fib.code}, // entry to PROG-fib
            {.value = 40},
        },
    .code =
        {
            {.op = OP_CONST, .reg = 2, .v1 = 0, .v2 = 0}, // load fib entry
            {.op = OP_CONST, .reg = 1, .v1 = 1, .v2 = 0}, // push argument 40
            {.op = OP_LCALL, .reg = 2, .v1 = 0, .v2 = 0}, // invoke fib
            {.op = OP_HALT, .reg = 0, .v1 = 0, .v2 = 0},  // halt after call
        },
};

int main() {}
