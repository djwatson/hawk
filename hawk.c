#define _DEFAULT_SOURCE

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bc.h"
#include "bigint.h"
#include "gc.h"
#include "hawk.h"
#include "types.h"
#include "vm.h"

bool verbose = false;
bool profile = false;
bool jit_dump_flag = false;
int64_t max_trace = INT64_MAX;

static struct option long_options[] = {
    {"verbose", no_argument, nullptr, 'v'},
    {"version", no_argument, nullptr, 0},
    {"profile", no_argument, nullptr, 'p'},
    {"joff", no_argument, nullptr, 'o'},
    {"dump", no_argument, nullptr, 'd'},
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
      // printf("Random: %s\n", optarg);
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

static void *gc_alloc_bigint(size_t sz) {
  uint64_t aligned = (uint64_t)((sz + 7) & ~((size_t)7));
  bn_t *bn = gc_alloc(aligned);
  bn->gc_hdr = BIGNUM_TAG;
  return bn;
}

static void gc_root_bigint_slot(bn_t **slot) {
  gc_add_root((const void *)slot, 1, PTR_TAG);
}

static void gc_unroot_bigint_slot(bn_t **slot) {
  gc_remove_root((const void *)slot, PTR_TAG);
}

static void init_bigint_hooks(void) {
  bn_set_alloc_hooks(gc_alloc_bigint, nullptr, gc_root_bigint_slot,
                     gc_unroot_bigint_slot);
}

int main(int argc, char *argv[]) {
  gc_init();
  init_bigint_hooks();

  auto filename = parse_args(argc, argv);
  char *filename_alloc = nullptr;

  auto ext = strrchr(filename, '.');
  if (!ext || strcmp(ext, ".bc") != 0) {
    size_t len = strlen(filename);
    size_t path_len = len + 3 + 1;
    filename_alloc = malloc(path_len);
    if (!filename_alloc) {
      printf("Must manually compile bitcode file for %s\n", filename);
      exit(-1);
    }
    snprintf(filename_alloc, path_len, "%s.bc", filename);
    if (access(filename_alloc, F_OK) == 0) {
      filename = filename_alloc;
    } else {
      printf("Must manually compile bitcode file for %s\n", filename_alloc);
      free(filename_alloc);
      exit(-1);
    }
  }

  auto start = gc_read_image(filename);
  if (!is_func(start)) {
    printf("Error loading %s\n", filename);
    exit(-1);
  }
  auto f = to_func(start);
  auto code_start = (bc *)&f->data[f->const_cnt * sizeof(gc_obj)];

  free(filename_alloc);
  (void)vm(code_start);
}
