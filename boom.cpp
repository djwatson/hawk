#include <getopt.h>
#include <unistd.h>

#include "jitdump.h"
#include "readbc.h"
#include "vm.h"

extern int joff;

static struct option long_options[] = {
    {"joff", no_argument, nullptr, 'o'},
    {"help", no_argument, nullptr, 'h'},
    {nullptr, no_argument, nullptr, 0},
};

void print_help() {
  printf("Usage: boom [OPTION]\n");
  printf("Available options are:\n");
  printf("  --joff\tTurn off jit\n");
  printf("  -h, --help\tPrint this help\n");
}

unsigned char __attribute__((weak)) bootstrap_scm_bc[0];
unsigned int __attribute__((weak)) bootstrap_scm_bc_len = 0;

int main(int argc, char *argv[]) {

  int verbose = 0;

  int c;
  while ((c = getopt_long(argc, argv, "hj:", long_options, nullptr)) != -1) {
    switch (c) {
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

  //GC_expand_hp(50000000);
  //jit_dump_init();
  if (bootstrap_scm_bc_len > 0) {
    auto start_func = readbc_image(bootstrap_scm_bc, bootstrap_scm_bc_len);
    run(start_func);
  }
  printf("Optind %i argc %i\n", optind, argc);
  for(int i = optind; i < argc; i++) {
    printf("Running script %s\n", argv[i]);
    auto start_func = readbc_file(argv[i]);
    run(start_func);
  }

  //jit_dump_close();

  return 0;
}
