#define _DEFAULT_SOURCE

#include <getopt.h>
#include <stdlib.h>

#include "bc.h"
#include "hawk.h"
#include "types.h"
#include "vm.h"

bool verbose = false;
bool profile = false;
bool jit_dump_flag = false;
int64_t max_trace = INT64_MAX; //!OCLINT

static struct option long_options[] = {
    {"verbose", no_argument, nullptr, 'v'},
    {"version", no_argument, nullptr, 0},
    {"profile", no_argument, nullptr, 'p'},
    {"joff", no_argument, nullptr, 'o'},
#ifdef HAVE_ELF_H
    {"dump", no_argument, nullptr, 'd'},
#endif
    {"help", no_argument, nullptr, 'h'},
    {"max-trace", required_argument, nullptr, 'm'},
    {nullptr, no_argument, nullptr, 0},
};

void print_help() {
  printf("Usage: hawk [OPTION] <script>.scm\n");
  printf("Available options are:\n");
  printf("      --joff     \tTurn off jit\n");
  printf("  -m, --max-trace\tStop JITting after # trace\n");
  printf("  -p, --profile  \tTurn on samplnig profiler\n");
  printf("      --dump     \tDump linux perf jit info\n");
  printf("      --version  \tPrint version\n");
  printf("  -s,            \tRandom schedule seed\n");
  printf("  -v, --verbose  \tTurn on verbose jit mode\n");
  printf("  -h, --help     \tPrint this help\n");
  // TODO(davejwatson): -I, -A, -D, --exe?, -s
}

static char *parse_args(int argc, char *argv[]) {
  int c;
  while ((c = getopt_long(argc, argv, "pvdhm:z:s:", long_options, nullptr)) !=
         -1) {
    switch (c) {
    case 'v':
      verbose = true;
      break;
    case 'o':
      max_trace = 0;
      break;
    case 'd':
      jit_dump_flag = true;
      break;
    case 'm':
      max_trace = atoi(optarg);
      break;
    case 's':
      printf("Random: %s\n", optarg);
      srandom(atoi(optarg));
      break;
    case 'p':
      profile = true;
      break;
    default:
      print_help();
      exit(-1);
      break;
    }
  }

  /* if (!argv[optind]) { */
  /*   print_help(); */
  /*   exit(-1); */
  /* } */

  return argv[optind];
}

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
            .header = {.type = FUNC_TAG},
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
            {OP_FUNC, 2, .data = 2},
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
  gc_obj consts[5];
  bc code[20];
} prog_sum_bc;
BCFUNC_FLEXARRAY_DIAG_POP

static symbol sum_sym;
static prog_sum_bc prog_sum = {
    .func =
        {
            .header = {.type = FUNC_TAG},
            .const_cnt = 5,
            .bc_cnt = 20,
        },
    .consts =
        {
            TAG_FIXNUM_LITERAL(2),
            tag_symbol(&sum_sym),
            TAG_FIXNUM_LITERAL(0),
            TAG_FIXNUM_LITERAL(1),
            TAG_FIXNUM_LITERAL(2),
        },
    .code =
        {
            {OP_FUNC, 3, .data = 3},
            {OP_KSHORT, 3, .data = TAG_FIXNUM_VALUE(0)},
            {OP_LT, 3, 1, 3},
            {OP_IF, 3, .data = 2},
            {OP_RET, 2, 0, 0},
            {OP_LOOKUP, 4, .data = 13},
            {OP_KSHORT, 5, .data = TAG_FIXNUM_VALUE(1)},
            {OP_SUB, 5, 1, 5},
            {OP_ADD, 6, 1, 2},
            {OP_CLOSURE_GET, 3, 4, 0},
            {OP_LCALLT, 3, 4, 0},
        },
};

static closure_s sum_clo = {.header =
                                {
                                    .type = CLOSURE_TAG,
                                },
                            .len = TAG_FIXNUM_LITERAL(1),
                            .v = {tag_func(&prog_sum)}};
static symbol sum_sym = {
    .header =
        {
            .type = SYMBOL_TAG,
        },

    .val = tag_closure(&sum_clo),
};

BCFUNC_FLEXARRAY_DIAG_PUSH
typedef struct {
  bcfunc func;
  gc_obj consts[2];
  bc code[5];
} fib_loader_bc;
BCFUNC_FLEXARRAY_DIAG_POP

static fib_loader_bc fib_loader = {
    .func =
        {
            .const_cnt = 2,
            .bc_cnt = 5,
        },
    .consts =
        {
            tag_func(&prog_fib), // entry to PROG-fib
                                 // tag_func(&prog_sum),
            // TAG_FIXNUM_LITERAL(1000000000),
            TAG_FIXNUM_LITERAL(40),
        },
    .code =
        {
            {OP_CONST, 0, .data = 4}, // load fib entry
            {OP_CONST, 2, .data = 3}, // push argument 40
            {OP_KSHORT, 3, .data = 0},
            {OP_LCALL, 0, 0, 0}, // invoke fib
            {OP_HALT, 0, 0, 0},  // halt after call
        },
};

int main(int argc, char *argv[]) {
  parse_args(argc, argv);

  auto res = vm(&fib_loader.code[0]);
  print_obj(res, stdout);
}
