#define _DEFAULT_SOURCE

#include <getopt.h>
#include <stdlib.h>

#include "bc.h"
#include "gc.h"
#include "hawk.h"
#include "readbc.h"
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

  if (!argv[optind]) {
    print_help();
    exit(-1);
  }

  return argv[optind];
}

int main(int argc, char *argv[]) {
  auto fp = __builtin_frame_address(0);
  gc_init(fp);

  auto filename = parse_args(argc, argv);

  auto start = heap_deserialize_from_file(filename);
  if (!is_func(start)) {
    printf("Error loading %s\n", filename);
    exit(-1);
  }
  auto f = to_func(start);
  auto code_start = (bc *)&f->data[f->const_cnt * sizeof(gc_obj)];

  (void)vm(code_start);
  // print_obj(vm(code_start), stdout);
}
