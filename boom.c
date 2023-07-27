#include <getopt.h>  // for no_argument, getopt_long, option
#include <stdbool.h> // for bool, false, true
#include <stdio.h>   // for printf
#include <stdlib.h>  // for exit
#include <string.h>  // for strcmp, strcpy, strlen

#include "gc.h" // for GC_init
#ifdef JIT
#include "jitdump.h" // for jit_dump_close, jit_dump_init
#endif
#ifdef PROFILER
#include "profiler.h" // for profiler_start, profiler_stop
#endif
#include "bytecode.h"
#include "readbc.h"       // for readbc_file, readbc_image
#include "symbol_table.h" // for symbol_table_find_cstr
#include "types.h"        // for from_c_str, symbol, CLOSURE_TAG, TRUE_REP
#include "vm.h"           // for run

#include "record.h"

#define auto __auto_type
#define nullptr NULL

extern int joff;

static struct option long_options[] = {
    {"profile", no_argument, nullptr, 'p'},
    {"joff", no_argument, nullptr, 'o'},
    {"help", no_argument, nullptr, 'h'},
    {"list", no_argument, nullptr, 'l'},
    {"max-trace", required_argument, nullptr, 'm'},
    {"heap-sz", required_argument, nullptr, 's'},
    {nullptr, no_argument, nullptr, 0},
};

void print_help() {
  printf("Usage: boom [OPTION]\n");
  printf("Available options are:\n");
#ifdef JIT
  printf("      --joff     \tTurn off jit\n");
  printf("  -m, --max-trace\tStop JITting after # trace\n");
#endif
  printf("  -l, --list     \tList bytecode and stop\n");
#ifdef PROFILER
  printf("  -p, --profile  \tSampling profiler\n");
#endif

  printf("  -h, --heap-sz  \tHeap size (in pages)\n");
  printf("  -h, --help     \tPrint this help\n");
}

unsigned char __attribute__((weak)) bootstrap_scm_bc[0];
unsigned int __attribute__((weak)) bootstrap_scm_bc_len = 0;

static bool list = false;
unsigned TRACE_MAX = 255;

// Call in to the compiled bytecode function (define (compile-file file) ...)
void compile_file(const char *file) {
  // Watch out for GC safety, from_c_str allocates.
  auto str = from_c_str(file);
  auto *sym = symbol_table_find_cstr("compile-file"); // DOes not allocate.
  long args[3] = {0, str, TRUE_REP};
  if ((sym == nullptr) || sym->val == UNDEFINED_TAG) {
    printf("Error: Attempting to compile a scm file, but can't find "
           "compile-file\n");
    exit(-1);
  }
  auto *clo = (closure_s *)(sym->val - CLOSURE_TAG);
  auto *func = (bcfunc *)clo->v[0];

  run(func, list ? 3 : 2, args);
}

int profile = 0;
size_t page_cnt = 12000;
int main(int argc, char *argv[]) {

  int verbose = 0;

  int c;
  while ((c = getopt_long(argc, argv, "slphj:", long_options, nullptr)) != -1) {
    switch (c) {
    case 'p':
      profile = 1;
      break;
    case 'v':
      verbose++;
      break;
    case 'o':
      joff = 1;
      break;
    case 'l':
      list = true;
      break;
    case 's':
      page_cnt = atoi(optarg);
      printf("Heap size %li MB\n", (page_cnt * 4096) / 1024 / 1024);
      break;
    case 'm':
      TRACE_MAX = atoi(optarg);
      printf("MAX TRACE is %i\n", TRACE_MAX);
      break;
    default:
      print_help();
      exit(-1);
    }
  }

  GC_init();
// GC_expand_hp(50000000);
#ifdef JIT
  jit_dump_init();
#endif
#ifdef PROFILER
  if (profile != 0) {
    profiler_start();
  }
#endif
  auto ojoff = joff;
  joff = 1;
  if (bootstrap_scm_bc_len > 0) {
    auto *start_func = readbc_image(bootstrap_scm_bc, bootstrap_scm_bc_len);
    printf("Running boot image...\n");
    run(start_func, 0, nullptr);
  }

  for (int i = optind; i < argc; i++) {
    auto len = strlen(argv[i]);
    if (len >= 4 && strcmp(".scm", argv[i] + len - 4) == 0) {
      char tmp[len + 1 + 3];
      strcpy(tmp, argv[i]);
      strcpy(tmp + len, ".bc");
      printf("Compiling script %s\n", argv[i]);
      compile_file(argv[i]);
      if (list) {
        break;
      }
      printf("Running script %s\n", tmp);
      joff = ojoff;
      auto *start_func = readbc_file(tmp);
      run(start_func, 0, nullptr);
    } else if (len >= 3 && strcmp(".bc", argv[i] + len - 3) == 0) {
      printf("Running script %s\n", argv[i]);
      joff = ojoff;
      auto *start_func = readbc_file(argv[i]);
      run(start_func, 0, nullptr);
    } else {
      printf("Unknown file type %s\n", argv[i]);
    }
  }

#ifdef PROFILER
  if (profile != 0) {
    profiler_stop();
  }
#endif

#ifdef JIT
  jit_dump_close();
  free_trace();
#endif
  free_script();
  free_vm();

  return 0;
}
