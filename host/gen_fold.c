#define _POSIX_C_SOURCE 200809
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ir.h"

#include "array.h"
#include "hashtable.h"
#include "zone_alloc.h"
#include "fold.h"

char *ir_names[] = {
#define X(name, type) #name,
    IR_OPS
#undef X
};

struct {
  const char *key;
  ir_ins_op value;
} *name_to_insn = nullptr;

static ir_ins_op nexttoken(char **p) {
  char *start = *p;
  while (**p != ' ' && **p != ')') {
    (*p)++;
  }
  **p = '\0';
  (*p)++;

  if (strcmp(start, "CONST") == 0) {
    return FOLD_ARG_CONST;
  }
  if (strcmp(start, "_") == 0) {
    return FOLD_ARG_ANY;
  }

  if (!sh_contains(name_to_insn, start)) {
    printf("Can't find token: %s\n", start);
    abort();
  }
  return sh_getv(name_to_insn, start);
}

static uint32_t hash(uint32_t key, uint32_t hashval) {
  key ^= key >> 16;
  key *= hashval;
  key ^= key >> 16;
  return key;
}

static void find_hash(zone *z, uint32_t *rules) {
  uint32_t *used = zone_malloc(z, arrlen(rules) * 2 * sizeof(uint32_t));
  size_t sz = arrlen(rules);

  for (size_t sz = arrlen(rules); sz <= arrlen(rules) * 2; sz++) {
    printf("//testing sz %li\n", sz);
    for (uint64_t hashcnt = 0; hashcnt < 1000000; hashcnt++) {
      bool success = true;
      memset(used, 0xff, sizeof(uint32_t) * sz);
      uint32_t hashval = rand();
      arr_for_each(rules, rule) {
        auto h = hash(rule & 0xffffff, hashval) % sz;
        if (used[h] != 0xffffffff) {
          success = false;
          break;
        }
        used[h] = rule;
      }
      if (success) {
        printf("static const uint32_t fold_hash[%li] = {\n", sz);
        for (uint64_t i = 0; i < sz; i++) {
          printf("0x%x,\n", used[i]);
        }
        printf("};\n\n");
        printf("static uint32_t hashkey(uint32_t key) {\n");
        printf("  key ^= key >> 16;\n");
        printf("  key *= 0x%x;\n", hashval);
        printf("  key ^= key >> 16;\n");
        printf("  key %%= %li;\n", sz);
        printf("  return key;\n");
        printf("}\n");
        return;
      }
    }
  }
  printf("FAILURE\n");
}

int main(int argc, char *argv[]) {
  uint64_t cur_func = 0;

  srand(0);

  zone z = {};
  if (argc != 2) {
    abort();
  }
  uint32_t *rules = nullptr;

  for (uint64_t i = 0; i < IR_INS_MAX; i++) {
    sh_put(&z, name_to_insn, ir_names[i], i);
  }
  sh_put(&z, name_to_insn, "_", FOLD_ARG_ANY);

  FILE *f = fopen(argv[1], "r");
  if (!f) {
    abort();
  }
  char *line = nullptr;
  size_t n = 0;
  ssize_t res;
  printf("static fold_func_type fold_func_table[] = {\n");
  while ((res = getline(&line, &n, f)) != -1) {
    if ((0 == strncmp(line, "IRFOLD(", 7))) {
      auto c = &line[7];
      auto op = nexttoken(&c);
      auto left = nexttoken(&c);
      auto right = nexttoken(&c);
      uint32_t rule = cur_func << 24 | op << 16 | left << 8 | right;
      arrput(&z, rules, rule);
    } else if (0 == strncmp(line, "IRFOLDF(", 8)) {
      auto c = &line[8];
      while (*c++ != ')') {
      };
      *(c - 1) = '\0';
      printf("%s,\n", &line[8]);
      cur_func++;
      if (cur_func >= 255) {
        abort();
      }
    }
  }
  printf("};\n\n");

  find_hash(&z, rules);

  free(line);
  zone_free(&z);
}
