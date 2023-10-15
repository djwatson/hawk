// Copyright 2023 Dave Watson

#include <getopt.h>  // for no_argument, getopt_long, option
#include <stdbool.h> // for bool, false, true
#include <stdint.h>
#include <stdio.h>  // for printf
#include <stdlib.h> // for exit
#include <string.h> // for strcmp, strcpy, strlen

#include "gc.h" // for GC_init
#ifdef JITDUMP
#include "jitdump.h" // for jit_dump_close, jit_dump_init
#endif
#ifdef PROFILER
#include "profiler.h" // for profiler_start, profiler_stop
#endif
#include "defs.h"
#include "readbc.h"       // for readbc_file, readbc_image
#include "symbol_table.h" // for symbol_table_find_cstr
#include "types.h"        // for from_c_str, symbol, CLOSURE_TAG, TRUE_REP
#include "vm.h"           // for run

void free_trace();

extern int joff;
#ifdef JITDUMP
extern bool jit_dump_flag;
#endif

static struct option long_options[] = {
    {"verbose", no_argument, nullptr, 'v'},
    {"profile", no_argument, nullptr, 'p'},
    {"joff", no_argument, nullptr, 'o'},
#ifdef JITDUMP
    {"dump", no_argument, nullptr, 'd'},
#endif
    {"help", no_argument, nullptr, 'h'},
    {"list", no_argument, nullptr, 'l'},
    {"max-trace", required_argument, nullptr, 'm'},
    {"exe", no_argument, nullptr, 'e'},
    {nullptr, no_argument, nullptr, 0},
};

void print_help() {
  printf("Usage: hawk [OPTION]\n");
  printf("Available options are:\n");
#ifdef JIT
  printf("      --joff     \tTurn off jit\n");
  printf("  -m, --max-trace\tStop JITting after # trace\n");
#endif
#ifdef JITDUMP
  printf("      --dump     \tDump linux perf jit info\n");
#endif
  printf("  -l, --list     \tList bytecode and stop\n");
#ifdef PROFILER
  printf("  -p, --profile  \tSampling profiler\n");
#endif
  printf("      --exe      \tGenerate an executable from the scheme file\n");

  printf("  -s, --heap-sz  \tHeap size (in pages)\n");
  printf("  -v, --verbose  \tTurn on verbose jit mode\n");
  printf("  -h, --help     \tPrint this help\n");
}

static bool list = false;
extern unsigned TRACE_MAX;

// Call in to the compiled bytecode function (define (compile-file file) ...)
void compile_file(const char *file) {
  // Watch out for GC safety, from_c_str allocates.
  auto str = from_c_str(file);
  auto sym = symbol_table_find_cstr("compile-file"); // DOes not allocate.
  gc_obj args[3] = {0, str, TRUE_REP};
  if ((sym == nullptr) || sym->val == UNDEFINED_TAG) {
    printf("Error: Attempting to compile a scm file, but can't find "
           "compile-file\n");
    exit(-1);
  }
  auto func = closure_code_ptr(to_closure(sym->val));

  run(func, list ? 3 : 2, args);
}

static char *escapeshellarg(char *str) {
  char *escStr;
  auto count = strlen(str) * 2 + 2 + 1;

  escStr = malloc(count);
  if (escStr == NULL) {
    return NULL;
  }
  uint64_t pos = 0;
  auto end = strlen(str);
  escStr[pos++] = '\'';
  for (uint64_t i = 0; i < end; i++) {
    if (str[i] == '\'') {
      escStr[pos++] = '\\';
      escStr[pos++] = '\'';
    } else {
      escStr[pos++] = str[i];
    }
  }
  escStr[pos++] = '\'';
  escStr[pos++] = '\0';
  return escStr;
}

void generate_exe(char *filename, const char *bc_name) {
  char tmp[512];

  snprintf(tmp, sizeof(tmp), "%s.c", filename);
  auto f = fopen(tmp, "w");
  auto fin = fopen(bc_name, "r");
  fputs("unsigned char exe_scm_bc[] = {\n", f);
  int res = fgetc(fin);
  uint64_t cnt = 0;
  while (res != EOF) {
    fprintf(f, "%i, ", res);
    res = fgetc(fin);
    cnt++;
  }
  fprintf(f, "};\nunsigned int exe_scm_bc_len = %lu;\n", cnt);
  fclose(fin);
  fclose(f);

  filename[strlen(filename) - 4] = '\0';

  char *arg = escapeshellarg(tmp);
  char *esc_filename = escapeshellarg(filename);
  char tmp2[701];
  snprintf(
      tmp2, 700,
      "clang -flto -o %s $LDFLAGS -L. -lhawk_exe -lhawk_vm %s -lcapstone -lm",
      esc_filename, arg);
  free(arg);
  free(esc_filename);
  printf("Running: %s\n", tmp2);
  if (system(tmp2)) {
    printf("Compile file error\n");
    exit(-1);
  }
}

extern bool verbose;
extern int profile;
extern size_t page_cnt;
static bool exe = false;

static void init() {
  GC_init();
#ifdef JITDUMP
  if (jit_dump_flag) {
    jit_dump_init();
  }
#endif
#ifdef PROFILER
  if (profile != 0) {
    profiler_start();
  }
#endif
  // TODO(djwatson) this should work without joff?
  auto old_joff = joff;
  joff = 1;
  load_bootstrap();
  joff = old_joff;
#ifdef AFL
  __AFL_INIT();
#endif
}

static void deinit() {
#ifdef PROFILER
  if (profile != 0) {
    profiler_stop();
  }
#endif

#ifdef JITDUMP
  if (jit_dump_flag) {
    jit_dump_close();
  }
#endif
#ifdef JIT
  free_trace();
#endif
  free_script();
  free_vm();
}

static void parse_args(int argc, char *argv[]) {
  int c;
  while ((c = getopt_long(argc, argv, "vlphjd:", long_options, nullptr)) !=
         -1) {
    switch (c) {
    case 'e':
      exe = true;
      break;
    case 'p':
      profile = 1;
      break;
    case 'v':
      verbose = true;
      break;
    case 'o':
      joff = 1;
      break;
    case 'l':
      list = true;
      break;
#ifdef JITDUMP
    case 'd':
      jit_dump_flag = true;
      break;
#endif
    case 'm':
      TRACE_MAX = atoi(optarg);
      printf("MAX TRACE is %u\n", TRACE_MAX);
      break;
    default:
      print_help();
      exit(-1);
      break;
    }
  }
}

int main(int argc, char *argv[]) {
  parse_args(argc, argv);

  init();

  for (int i = optind; i < argc; i++) {
    auto len = strlen(argv[i]);
    if (len >= 4 && strcmp(".scm", argv[i] + len - 4) == 0) {
      uint64_t tmplen = len + 1 + 3;
      char *tmp = malloc(tmplen);
      snprintf(tmp, tmplen, "%s.bc", argv[i]);
      printf("Compiling script %s\n", argv[i]);
      {
        auto old_joff = joff;
        joff = 1;
        compile_file(argv[i]);
        joff = old_joff;
      }
      if (exe) {
        generate_exe(argv[i], tmp);
      }
      if (list || exe) {
        free(tmp);
        break;
      }
      printf("Running script %s\n", tmp);
      auto start_func = readbc_file(tmp);
      run(start_func, 0, nullptr);
      free(tmp);
    } else if (len >= 3 && strcmp(".bc", argv[i] + len - 3) == 0) {
      printf("Running script %s\n", argv[i]);
      auto start_func = readbc_file(argv[i]);
      run(start_func, 0, nullptr);
    } else {
      printf("Unknown file type %s\n", argv[i]);
    }
  }

  deinit();

  return 0;
}
