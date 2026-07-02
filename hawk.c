#define _DEFAULT_SOURCE

#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bc.h"
#include "bigint.h"
#include "gc.h"
#include "hawk.h"
#include "runtime.h"
#include "types.h"
#include "util/array.h"
#include "vm.h"

#ifndef HAWK_CC
#define HAWK_CC "cc"
#endif
#ifndef HAWK_CORE_LIB
#define HAWK_CORE_LIB "-lhawk_core"
#endif
#ifndef HAWK_EXE_EXPORT_FLAG
#define HAWK_EXE_EXPORT_FLAG "-rdynamic"
#endif
#ifndef HAWK_DEFAULT_LIBRARY_PATH
#define HAWK_DEFAULT_LIBRARY_PATH ""
#endif

uint32_t hlog_mask = HLOG_NONE;
bool profile = false;
bool jit_dump_flag = false;
int64_t max_trace = INT64_MAX;
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
    {"exe", no_argument, nullptr, 'e'},
    {"image", required_argument, nullptr, 'i'},
    {"help", no_argument, nullptr, 'h'},
    {"max-trace", required_argument, nullptr, 'm'},
    {nullptr, no_argument, nullptr, 0},
};

extern const uint8_t embedded_image[];
extern const size_t embedded_image_size;
extern const bool embedded_image_compressed;
extern const bool embedded_image_is_program;

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
  if (embedded_image_is_program) {
    printf("Usage: hawk [OPTION] [arg ...]\n");
  } else {
    printf("Usage: hawk [OPTION] [<script> [arg ...]]\n");
  }
  printf("Normal options are:\n");
  printf("  -o, --joff     \tTurn off jit\n");
  printf("  -i, --image    \tLoad explicit .bc image file\n");
  printf("  -D name        \tAdd feature identifier\n");
  printf("  -I directory   \tPrepend library search directory\n");
  printf("  -A directory   \tAppend library search directory\n");
  printf("  -p, --profile  \tTurn on samplnig profiler\n");
  printf("      --version  \tPrint version\n");
  printf("      --list     \tCompile script without running it\n");
  if (!embedded_image_is_program) {
    printf("      --exe      \tGenerate executable from Scheme file\n");
  }
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
  bool exe;
} parse_result;

static char *absolute_path_arg(char const *path) {
  if (path[0] == '/') {
    return strdup(path);
  }
  char *cwd = getcwd(nullptr, 0);
  if (!cwd) {
    perror("getcwd");
    exit(-1);
  }
  size_t len = strlen(cwd) + 1 + strlen(path) + 1;
  char *out = malloc(len);
  if (!out) {
    abort();
  }
  snprintf(out, len, "%s/%s", cwd, path);
  free(cwd);
  return out;
}

static parse_result parse_args(int argc, char *argv[]) {
  int c;
  parse_result out = {0};
  int option_index = 0;
#ifdef RANDOM_SCHEDULE
#define HAWK_SHORT_OPTS "+pv::dheoD:I:A:m:s:i:"
#else
#define HAWK_SHORT_OPTS "+pv::dheoD:I:A:m:i:"
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
    case 'e':
      out.exe = true;
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
      arrput(out.prepend_paths, absolute_path_arg(optarg));
      break;
    case 'A':
      arrput(out.append_paths, absolute_path_arg(optarg));
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
  if (!embedded_image_is_program && !after_separator && optind < argc) {
    out.script = argv[optind];
    command_arg_idx = optind + 1;
  }
  if (command_arg_idx < argc && strcmp(argv[command_arg_idx], "--") == 0) {
    command_arg_idx++;
  }
  out.command_arg_idx = command_arg_idx;
  return out;
}

static char *xstrdup(const char *str) {
  char *out = strdup(str);
  if (!out) {
    perror("strdup");
    exit(EXIT_FAILURE);
  }
  return out;
}

static void link_executable(const char *output, const char *image_source) {
  char *argv[] = {
      HAWK_CC,
      "-std=c23",
      "-O2",
      "-g",
      "-o",
      (char *)output,
      (char *)image_source,
      HAWK_CORE_LIB,
      HAWK_EXE_EXPORT_FLAG,
      nullptr,
  };
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    exit(EXIT_FAILURE);
  }
  if (pid == 0) {
    execvp(HAWK_CC, argv);
    perror("execvp");
    _exit(127);
  }
  int status;
  if (waitpid(pid, &status, 0) < 0) {
    perror("waitpid");
    exit(EXIT_FAILURE);
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    fprintf(stderr, "hawk --exe: link failed\n");
    exit(EXIT_FAILURE);
  }
}

EXPORT bool hawk_have_zstd(void) {
#ifdef HAVE_ZSTD
  return true;
#else
  return false;
#endif
}

EXPORT int32_t hawk_dump_image_and_make_exe(gc_obj clo, gc_obj image_obj,
                                            gc_obj source_obj,
                                            gc_obj output_obj) {
  if (!is_string(image_obj) || !is_string(source_obj) ||
      !is_string(output_obj)) {
    fprintf(stderr, "hawk --exe: invalid output path\n");
    exit(EXIT_FAILURE);
  }
  char *source = xstrdup(to_string(source_obj)->str);
  char *output = xstrdup(to_string(output_obj)->str);
  gc_dump_image(clo, image_obj, tag_fixnum(19));
  link_executable(output, source);
  exit(EXIT_SUCCESS);
}

EXPORT int main(int argc, char *argv[]) {
  raise_fd_limit();
  gc_init();

  parse_result args = parse_args(argc, argv);
  auto image = args.image;
  auto script = args.script;
  if (args.exe && embedded_image_is_program) {
    fprintf(stderr, "--exe is not available in generated executables\n");
    exit(EXIT_FAILURE);
  }
  if (args.exe && !script) {
    fprintf(stderr, "--exe requires a Scheme source file\n");
    exit(EXIT_FAILURE);
  }
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
                            embedded_image_compressed);
    } else {
      start = gc_read_image_file(image_name);
    }
  }
  if (!is_closure(start)) {
    printf("Error loading %s\n", image_name);
    exit(-1);
  }

  gc_obj script_arg = UNDEFINED;
  gc_obj exe_arg = UNDEFINED;
  if (script) {
    gc_add_root((const void *)&start, 1, 0);
    script_arg = make_string(script);
    gc_remove_root((const void *)&start, 0);
    exe_arg = args.exe ? TRUE_REP : FALSE_REP;
  }

  (void)vm(start, script_arg, exe_arg);
  if (args.exe) {
    fprintf(stderr, "hawk --exe: image generation returned unexpectedly\n");
    exit(EXIT_FAILURE);
  }
}

EXPORT gc_obj hawk_command_line_features(void) {
  return make_string_list(command_line_features, arrlen(command_line_features));
}

EXPORT gc_obj hawk_command_line_prepend_paths(void) {
  return make_string_list(command_line_prepend_paths,
                          arrlen(command_line_prepend_paths));
}

EXPORT gc_obj hawk_default_library_paths(void) {
  char *paths[] = {HAWK_DEFAULT_LIBRARY_PATH};
  return HAWK_DEFAULT_LIBRARY_PATH[0] ? make_string_list(paths, 1) : NIL;
}

EXPORT gc_obj hawk_command_line_append_paths(void) {
  return make_string_list(command_line_append_paths,
                          arrlen(command_line_append_paths));
}

EXPORT gc_obj hawk_command_line_list(void) {
  return command_line_list ? TRUE_REP : FALSE_REP;
}
