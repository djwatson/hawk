#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>

#include "gc.h"
#include "jitdump.h"
#include "readbc.h"
#include "symbol_table.h"
#include "types.h"
#include "vm.h"
#include "profiler.h"

extern int joff;

static struct option long_options[] = {
    {"profile", no_argument, nullptr, 'p'},
    {"joff", no_argument, nullptr, 'o'},
    {"help", no_argument, nullptr, 'h'},
    {nullptr, no_argument, nullptr, 0},
};

void print_help() {
  printf("Usage: boom [OPTION]\n");
  printf("Available options are:\n");
  printf("  --joff\tTurn off jit\n");
  printf("  -p, --profile\tSampling profiler\n");
  printf("  -h, --help\tPrint this help\n");
}

unsigned char __attribute__((weak)) bootstrap_scm_bc[0];
unsigned int __attribute__((weak)) bootstrap_scm_bc_len = 0;

// Call in to the compiled bytecode function (define (compile-file file) ...)
void compile_file(const char *file) {
  // Watch out for GC safety, from_c_str allocates.
  auto str = from_c_str(file);
  auto sym = symbol_table_find_cstr("compile-file"); // DOes not allocate.
  long args[2] = {0, str};
  if (!sym || sym->val == UNDEFINED_TAG) {
    printf("Error: Attempting to compile a scm file, but can't find "
           "compile-file\n");
    exit(-1);
  }
  auto clo = (closure_s *)(sym->val - CLOSURE_TAG);
  auto func = (bcfunc *)clo->v[0];

  run(func, 2, args);
}

int profile = 0;
int main(int argc, char *argv[]) {

  int verbose = 0;

  int c;
  while ((c = getopt_long(argc, argv, "phj:", long_options, nullptr)) != -1) {
    switch (c) {
    case 'p':
      profile = 1;
      break;
    case 's':
      break;
    case 'v':
      verbose++;
      break;
    case 'o':
      joff = 1;
      break;
    default:
      print_help();
      exit(-1);
    }
  }

  GC_init();
  // GC_expand_hp(50000000);
  // jit_dump_init();
  if (profile) {
    profiler_start();
  }
  if (bootstrap_scm_bc_len > 0) {
    auto start_func = readbc_image(bootstrap_scm_bc, bootstrap_scm_bc_len);
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
      printf("Running script %s\n", tmp);
      auto start_func = readbc_file(tmp);
      run(start_func, 0, nullptr);
    } else if (len >= 3 && strcmp(".bc", argv[i] + len - 3) == 0) {
      printf("Running script %s\n", argv[i]);
      auto start_func = readbc_file(argv[i]);
      run(start_func, 0, nullptr);
    } else {
      printf("Unknown file type %s\n", argv[i]);
    }
  }

  // jit_dump_close();
  if (profile) {
    profiler_stop();
  }

  return 0;
}
