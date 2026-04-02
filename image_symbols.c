#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gc.h"
#include "hawk.h"
#include "types.h"
#include "util/array.h"
#include "util/hashtable.h"

bool verbose = false;
bool profile = false;
bool jit_dump_flag = false;
int64_t max_trace = 0;

void profiler_set_in_gc(bool active) { (void)active; }
void vm_trace_reset(void) {}

typedef struct {
  gc_header *key;
  bool value;
} seen_entry;

typedef struct {
  bool strings;
  bool symbols;
  bool functions;
} dump_options;

static seen_entry *seen;
static gc_header **worklist;
static dump_options options;

static void image_error(char const *path, char const *msg) {
  fprintf(stderr, "%s: %s\n", path, msg);
  exit(EXIT_FAILURE);
}

static void print_usage(char const *argv0) {
  fprintf(stderr,
          "usage: %s [--strings] [--symbols] [--functions] <image.bc>\n",
          argv0);
}

static char const *parse_args(int argc, char **argv) {
  char const *path = nullptr;
  for (int i = 1; i < argc; i++) {
    char const *arg = argv[i];
    if (strcmp(arg, "--strings") == 0) {
      options.strings = true;
      continue;
    }
    if (strcmp(arg, "--symbols") == 0) {
      options.symbols = true;
      continue;
    }
    if (strcmp(arg, "--functions") == 0) {
      options.functions = true;
      continue;
    }
    if (arg[0] == '-') {
      print_usage(argv[0]);
      exit(EXIT_FAILURE);
    }
    if (path) {
      print_usage(argv[0]);
      exit(EXIT_FAILURE);
    }
    path = arg;
  }
  if (!options.strings && !options.symbols && !options.functions) {
    options.symbols = true;
  }
  if (!path) {
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
  }
  return path;
}

static void maybe_print_obj(gc_header *header) {
  switch (header->type) {
  case STRING_TAG:
    if (options.strings) {
      puts(((string_s *)header)->str);
    }
    return;
  case SYMBOL_TAG:
    if (options.symbols) {
      string_s *name = get_sym_name((symbol *)header);
      if (name) {
        puts(name->str);
      }
    }
    return;
  case FUNC_TAG:
    if (options.functions) {
      string_s *name = to_string(((bcfunc *)header)->name);
      puts(name->str);
    }
    return;
  default:
    return;
  }
}

static void enqueue_obj(gc_obj obj) {
  if (!is_heap_object(obj)) {
    return;
  }
  gc_header *header = to_gc_header(obj);
  if (hm_contains(seen, header)) {
    return;
  }
  hm_put(seen, header, true);
  maybe_print_obj(header);
  arrput(worklist, header);
}

static void trace_field(gc_obj *slot, void *ctx) {
  (void)ctx;
  enqueue_obj(*slot);
}

int main(int argc, char **argv) {
  char const *path = parse_args(argc, argv);
  gc_init();
  gc_obj start = gc_read_image_file(path);
  enqueue_obj(start);
  while (arrlen(worklist) > 0) {
    gc_header *obj = *arrlast(worklist);
    arrpop(worklist);
    trace_heap_object(obj, trace_field, nullptr);
  }
  arrfree(worklist);
  hm_free(seen);
  gc_free();
  return EXIT_SUCCESS;
}
