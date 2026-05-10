#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bigint.h"

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
  bool dump_sizes;
} dump_options;

static seen_entry *seen;
static gc_header **worklist;
static dump_options options;

typedef struct {
  char const *name;
  uint64_t count;
  uint64_t total_size;
} type_stats;

static type_stats *type_statistics;

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
    if (strcmp(arg, "--sizes") == 0) {
      options.dump_sizes = true;
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
  if (!options.strings && !options.symbols && !options.functions &&
      !options.dump_sizes) {
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

static void record_type_stats(gc_header *header) {
  if (!options.dump_sizes) {
    return;
  }

  char const *type_name = nullptr;
  uint64_t size = 0;

  switch (header->type) {
  case FLONUM_TAG:
    type_name = "flonum";
    size = sizeof(flonum_s);
    break;
  case BIGNUM_TAG: {
    type_name = "bignum";
    auto bn = (bn_t *)header;
    size = heap_align(sizeof(bn_t) + (size_t)bn->alloc * sizeof(uint64_t));
    break;
  }
  case RATNUM_TAG:
    type_name = "ratnum";
    size = sizeof(ratnum_s);
    break;
  case COMPNUM_TAG:
    type_name = "compnum";
    size = sizeof(compnum_s);
    break;
  case STRING_TAG: {
    type_name = "string";
    auto str = (string_s *)header;
    size = heap_align(sizeof(string_s) + (size_t)to_fixnum(str->len) + 1);
    break;
  }
  case SYMBOL_TAG:
    type_name = "symbol";
    size = sizeof(symbol);
    break;
  case VECTOR_TAG:
  case CONT_TAG:
  case RECORD_TAG: {
    auto vec = (vector_s *)header;
    type_name = header->type == VECTOR_TAG ? "vector"
                : header->type == CONT_TAG ? "cont"
                                           : "record";
    size = sizeof(vector_s) + (size_t)to_fixnum(vec->len) * sizeof(gc_obj);
    break;
  }
  case CONS_TAG:
    type_name = "cons";
    size = sizeof(cons_s);
    break;
  case CLOSURE_TAG: {
    type_name = "closure";
    auto clo = (closure_s *)header;
    size = sizeof(closure_s) + (size_t)to_fixnum(clo->len) * sizeof(gc_obj);
    break;
  }
  case FUNC_TAG: {
    type_name = "function";
    auto func = (bcfunc *)header;
    size = heap_align(sizeof(bcfunc) + (func->const_cnt * sizeof(gc_obj)) +
                      (func->bc_cnt * sizeof(bc)));
    break;
  }
  case BOX_TAG:
    type_name = "box";
    size = sizeof(gc_obj);
    break;
  default:
    return;
  }

  // Find or create entry
  for (uint64_t i = 0; i < arrlen(type_statistics); i++) {
    if (strcmp(type_statistics[i].name, type_name) == 0) {
      type_statistics[i].count++;
      type_statistics[i].total_size += size;
      return;
    }
  }

  type_stats new_entry = {
      .name = type_name,
      .count = 1,
      .total_size = size,
  };
  arrput(type_statistics, new_entry);
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
  record_type_stats(header);
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

  if (options.dump_sizes) {
    printf("\n=== Object Size Statistics ===\n");
    uint64_t grand_total = 0;
    uint64_t total_count = 0;
    for (uint64_t i = 0; i < arrlen(type_statistics); i++) {
      grand_total += type_statistics[i].total_size;
      total_count += type_statistics[i].count;
    }
    for (uint64_t i = 0; i < arrlen(type_statistics); i++) {
      double pct = grand_total > 0 ? (double)type_statistics[i].total_size /
                                         grand_total * 100.0
                                   : 0.0;
      printf("%-12s: count=%-8lu total_size=%-10lu bytes (%5.1f%%)\n",
             type_statistics[i].name, type_statistics[i].count,
             type_statistics[i].total_size, pct);
    }
    printf("%-12s: count=%-8lu total_size=%-10lu bytes\n", "TOTAL", total_count,
           grand_total);
  }

  arrfree(worklist);
  arrfree(type_statistics);
  hm_free(seen);
  gc_free();
  return EXIT_SUCCESS;
}
