#define _DEFAULT_SOURCE

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "bc.h"
#include "bigint.h"
#include "gc.h"
#include "hawk.h"
#include "runtime.h"
#include "types.h"
#include "util/array.h"
#include "vm.h"

uint32_t hlog_mask = HLOG_NONE;
bool profile = false;
bool jit_dump_flag = false;
int64_t max_trace = INT64_MAX;
char *command_line_program_name = nullptr;
int command_line_argc = 0;
char **command_line_argv = nullptr;
static char **command_line_features;
static char **command_line_prepend_paths;
static char **command_line_append_paths;
static bool command_line_list;

static struct option long_options[] = {
    {"verbose", optional_argument, nullptr, 'v'},
    {"version", no_argument, nullptr, 0},
    {"profile", no_argument, nullptr, 'p'},
    {"joff", no_argument, nullptr, 'o'},
    {"dump", no_argument, nullptr, 'd'},
    {"list", no_argument, nullptr, 0},
    {"image", required_argument, nullptr, 'i'},
    {"help", no_argument, nullptr, 'h'},
    {"max-trace", required_argument, nullptr, 'm'},
    {nullptr, no_argument, nullptr, 0},
};

extern const uint8_t embedded_image[];
extern const size_t embedded_image_size;

// On OSX, dynamic.scm test fails because of open file limits (as low
// as 256 open files)
static void raise_fd_limit() {
  struct rlimit lim;
  if (getrlimit(RLIMIT_NOFILE, &lim) != 0) {
    return;
  }
  rlim_t target = 4096;
  if (lim.rlim_max != RLIM_INFINITY && target > lim.rlim_max) {
    target = lim.rlim_max;
  }
  if (lim.rlim_cur < target) {
    lim.rlim_cur = target;
    (void)setrlimit(RLIMIT_NOFILE, &lim);
  }
}

void print_help() {
  printf("Usage: hawk [OPTION] [<script> [arg ...]]\n");
  printf("Normal options are:\n");
  printf("  -o, --joff     \tTurn off jit\n");
  printf("  -i, --image    \tLoad explicit .bc image file\n");
  printf("  -D name        \tAdd feature identifier\n");
  printf("  -I directory   \tPrepend library search directory\n");
  printf("  -A directory   \tAppend library search directory\n");
  printf("  -p, --profile  \tTurn on samplnig profiler\n");
  printf("      --version  \tPrint version\n");
  printf("      --list     \tCompile script without running it\n");
  printf("  -h, --help     \tPrint this help\n");
  printf("  -v, --verbose[=cats]\tVerbose logging: gc,trace,record,jit,regalloc,asm,ir\n");
  printf("Debug options are:\n");
  printf("  -m, --max-trace\tStop JITting after # trace\n");
  printf("  -d, --dump     \tDump linux perf jit info\n");
#ifdef RANDOM_SCHEDULE
  printf("  -s             \tRandom schedule seed\n");
#endif
  // TODO(davejwatson): --exe?
}

typedef struct {
  char *image;
  char *script;
  char **features;
  char **prepend_paths;
  char **append_paths;
  int command_arg_idx;
  bool list;
} parse_result;

static parse_result parse_args(int argc, char *argv[]) {
  int c;
  parse_result out = {0};
  int option_index = 0;
#ifdef RANDOM_SCHEDULE
#define HAWK_SHORT_OPTS "+pv::dhoD:I:A:m:s:i:"
#else
#define HAWK_SHORT_OPTS "+pv::dhoD:I:A:m:i:"
#endif
  while ((c = getopt_long(argc, argv, HAWK_SHORT_OPTS, long_options,
                          &option_index)) != -1) {
    switch (c) {
    case 'v':
      if (optarg) {
        if (!hlog_parse(optarg)) {
          fprintf(stderr, "Invalid verbose category: %s\n", optarg);
          exit(-1);
        }
      } else {
        hlog_mask = HLOG_ALL;
      }
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
#ifdef RANDOM_SCHEDULE
    case 's':
      // printf("Random: %s\n", optarg);
      srandom(atoi(optarg));
      break;
#endif
    case 'p':
      profile = true;
      break;
    case 'i':
      out.image = optarg;
      break;
    case 'D':
      arrput(out.features, optarg);
      break;
    case 'I':
      arrput(out.prepend_paths, optarg);
      break;
    case 'A':
      arrput(out.append_paths, optarg);
      break;
    case 0:
      if (strcmp(long_options[option_index].name, "version") == 0) {
        printf("hawk\n");
        exit(0);
      } else if (strcmp(long_options[option_index].name, "list") == 0) {
        out.list = true;
      }
      break;
    default:
      print_help();
      exit(-1);
      break;
    }
  }
#undef HAWK_SHORT_OPTS

  bool after_separator = optind > 1 && strcmp(argv[optind - 1], "--") == 0;
  int command_arg_idx = optind;
  if (!after_separator && optind < argc) {
    out.script = argv[optind];
    command_arg_idx = optind + 1;
  }
  if (command_arg_idx < argc && strcmp(argv[command_arg_idx], "--") == 0) {
    command_arg_idx++;
  }
  out.command_arg_idx = command_arg_idx;
  return out;
}

EXPORT int main(int argc, char *argv[]) {
  raise_fd_limit();
  gc_init();
  command_line_program_name = argv[0];

  parse_result args = parse_args(argc, argv);
  auto image = args.image;
  auto script = args.script;
  command_line_features = args.features;
  command_line_prepend_paths = args.prepend_paths;
  command_line_append_paths = args.append_paths;
  command_line_list = args.list;
  if (args.command_arg_idx < argc) {
    command_line_argc = argc - args.command_arg_idx;
    command_line_argv = &argv[args.command_arg_idx];
  }
  if (script) {
    command_line_argc++;
    command_line_argv = &argv[args.command_arg_idx - 1];
  }

  gc_obj start;
  const char *image_name = image ? image :
#ifdef HAVE_ZSTD
      "boot/img.scm.bc.zstd";
#else
      "boot/img.scm.bc";
#endif
  if (image) {
    start = gc_read_image_file(image);
  } else {
    if (embedded_image_size > 0) {
      start = gc_read_image(embedded_image, embedded_image_size, image_name,
#ifdef HAVE_ZSTD
                            true
#else
                            false
#endif
      );
    } else {
      start = gc_read_image_file(image_name);
    }
  }
  if (!is_func(start)) {
    printf("Error loading %s\n", image_name);
    exit(-1);
  }

  gc_obj script_arg = UNDEFINED;
  if (script) {
    gc_add_root((const void *)&start, 1, 0);
    script_arg = make_string(script);
    gc_remove_root((const void *)&start, 0);
  }

  auto f = to_func(start);
  (void)vm(f, script_arg);
}

EXPORT gc_obj hawk_command_line_features(void) {
  return make_string_list(command_line_features, arrlen(command_line_features));
}

EXPORT gc_obj hawk_command_line_prepend_paths(void) {
  return make_string_list(command_line_prepend_paths,
                          arrlen(command_line_prepend_paths));
}

EXPORT gc_obj hawk_command_line_append_paths(void) {
  return make_string_list(command_line_append_paths,
                          arrlen(command_line_append_paths));
}

EXPORT gc_obj hawk_command_line_list(void) {
  return command_line_list ? TRUE_REP : FALSE_REP;
}
