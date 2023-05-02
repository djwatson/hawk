#include <getopt.h>
#include <unistd.h>

#include "readbc.h"
#include "vm.h"

extern int joff;
long on_trace = 0;
long off_trace = 0;

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

  readbc();
  run();
  free_script();

  printf("Off trace percent: %.02f\n", (float)off_trace / (float) (on_trace + off_trace) * 100.0);
  return 0;
}
