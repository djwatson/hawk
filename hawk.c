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
char *command_line_program_name = nullptr;
int command_line_argc = 0;
char **command_line_argv = nullptr;

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

extern const uint8_t embedded_image[];
extern const size_t embedded_image_size;

void print_help() {
  printf("Usage: hawk [OPTION] [<script>.scm]\n");
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

typedef struct {
  char *filename;
  int command_arg_idx;
} parse_result;

static parse_result parse_args(int argc, char *argv[]) {
  int c;
  int option_index = 0;
  while ((c = getopt_long(argc, argv, "+pvdhm:z:s:", long_options,
                          &option_index)) !=
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
    case 0:
      if (strcmp(long_options[option_index].name, "version") == 0) {
        printf("hawk\n");
        exit(0);
      }
      break;
    default:
      print_help();
      exit(-1);
      break;
    }
  }

  bool after_separator =
      optind > 1 && strcmp(argv[optind - 1], "--") == 0;
  int command_arg_idx = optind;
  char *filename = nullptr;
  if (!after_separator && optind < argc) {
    filename = argv[optind];
    command_arg_idx = optind + 1;
  }
  if (command_arg_idx < argc && strcmp(argv[command_arg_idx], "--") == 0) {
    command_arg_idx++;
  }
  parse_result out = {
      .filename = filename,
      .command_arg_idx = command_arg_idx,
  };
  return out;
}

int main(int argc, char *argv[]) {
  gc_init();
  command_line_program_name = argv[0];

  parse_result args = parse_args(argc, argv);
  auto filename = args.filename;
  char *filename_alloc = nullptr;
  if (args.command_arg_idx < argc) {
    command_line_argc = argc - args.command_arg_idx;
    command_line_argv = &argv[args.command_arg_idx];
  }
  if (filename) {
    command_line_argc++;
    command_line_argv = &argv[args.command_arg_idx - 1];
  }

  gc_obj start;
  if (filename) {
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
    start = gc_read_image_file(filename);
  } else {
    filename = "lib/img.scm.bc";
    if (embedded_image_size > 0) {
      start = gc_read_image(embedded_image, embedded_image_size, filename);
    } else {
      start = gc_read_image_file(filename);
    }
  }
  if (!is_func(start)) {
    printf("Error loading %s\n", filename);
    exit(-1);
  }
  auto f = to_func(start);

  free(filename_alloc);
  (void)vm(f);
}
