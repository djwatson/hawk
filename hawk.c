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
            .const_cnt = 5,
            .bc_cnt = 20,
        },
    .consts =
        {
            tag_fixnum(2),
            tag_symbol(&fib_sym),
            tag_fixnum(0),
            tag_fixnum(1),
            tag_fixnum(2),
        },
    .code =
        {
            {OP_FUNC, 2, 0, 0},
            {OP_CONST, 2, .data = 11},
            {OP_LT, 2, 1, 2},         
            {OP_IF, 2, .data = 2},
            {OP_RET, 1, 0, 0},    
            {OP_LOOKUP, 3, .data = 13},
            {OP_CONST, 4, .data = 10},       
            {OP_SUB, 4, 1, 4},         
            {OP_CONST, 2, .data = 14}, 
            {OP_CLOSURE_GET, 2, 3, 2}, 
            {OP_LCALL, 2, 2, 0},       
            {OP_LOOKUP, 4, .data = 19},
            {OP_CONST, 5, .data = 14}, 
            {OP_SUB, 5, 1, 5},         
            {OP_CONST, 3, .data = 20}, 
            {OP_CLOSURE_GET, 3, 4, 3}, 
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
	  tag_func(&prog_fib), // entry to PROG-fib
            tag_fixnum(40),
        },
    .code =
        {
            {OP_CONST, 0, .data = 4}, // load fib entry
            {OP_CONST, 2, .data = 3}, // push argument 40
            {OP_LCALL, 0, 0, 0}, // invoke fib
            {OP_HALT, 0, 0, 0},  // halt after call
        },
};

int main() {
  auto res = vm(&fib_loader.code[0]);
  print_obj(res, stdout);
}
