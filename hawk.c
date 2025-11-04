#include "hawk.h"
#include "bc.h"
#include "types.h"
#include "vm.h"

BCFUNC_FLEXARRAY_DIAG_PUSH
typedef struct {
  bcfunc func;
  gc_obj consts[5];
  bc code[20];
} prog_fib_bc;
BCFUNC_FLEXARRAY_DIAG_POP

static symbol fib_sym;
static prog_fib_bc prog_fib = {
    .func =
        {
            .header = {.type = FUNC_TAG, .rc = 0},
            .const_cnt = 5,
            .bc_cnt = 20,
        },
    .consts =
        {
            TAG_FIXNUM_LITERAL(2),
            tag_symbol(&fib_sym),
            TAG_FIXNUM_LITERAL(0),
            TAG_FIXNUM_LITERAL(1),
            TAG_FIXNUM_LITERAL(2),
        },
    .code =
        {
            {OP_FUNC, 2, 0, 0},
            {OP_KSHORT, 2, .data = TAG_FIXNUM_VALUE(2)},
            {OP_LT, 2, 1, 2},
            {OP_IF, 2, .data = 2},
            {OP_RET, 1, 0, 0},
            {OP_LOOKUP, 3, .data = 13},
            {OP_KSHORT, 4, .data = TAG_FIXNUM_VALUE(1)},
            {OP_SUB, 4, 1, 4},
            {OP_CLOSURE_GET, 2, 3, 0},
            {OP_LCALL, 2, 2, 0},
            {OP_LOOKUP, 4, .data = 18},
            {OP_KSHORT, 5, .data = TAG_FIXNUM_VALUE(2)},
            {OP_SUB, 5, 1, 5},
            {OP_CLOSURE_GET, 3, 4, 0},
            {OP_LCALL, 3, 3, 0},
            {OP_ADD, 2, 2, 3},
            {OP_RET, 2, 0, 0},
            {OP_HALT, 0, 0, 0},
        },
};

static closure_s fib_clo = {.header =
                                {
                                    .type = CLOSURE_TAG,
                                },
                            .len = TAG_FIXNUM_LITERAL(1),
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
            tag_func(&prog_fib), // entry to PROG-fib
            TAG_FIXNUM_LITERAL(40),
        },
    .code =
        {
            {OP_CONST, 0, .data = 4}, // load fib entry
            {OP_CONST, 2, .data = 3}, // push argument 40
            {OP_LCALL, 0, 0, 0},      // invoke fib
            {OP_HALT, 0, 0, 0},       // halt after call
        },
};

int main() {
  auto res = vm(&fib_loader.code[0]);
  print_obj(res, stdout);
}
