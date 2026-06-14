#define _POSIX_C_SOURCE 200809
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ir.h"

#include "array.h"
#include "fold.h"
#include "hashtable.h"

char *ir_names[] = {
#define X(name, type, sideeff) #name,
    IR_OPS
#undef X
};

struct {
  const char *key;
  ir_ins_op value;
} *name_to_insn = nullptr;

static uint8_t nexttoken(char **p) {
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

static bool try_hash(uint32_t *used, uint32_t *rules, size_t sz, uint32_t r) {
  memset(used, 0xff, sizeof(uint32_t) * (sz + 1));
  arr_for_each(rules, rule) {
    uint32_t key = rule & 0xffffff;
    uint32_t h = hash(key, r) % sz;
    if (used[h] == 0xffffffff) {
      used[h] = rule;
      continue;
    }
    if (used[h + 1] != 0xffffffff) {
      if (h >= sz - 1 || used[h + 2] != 0xffffffff) {
        return false;
      }
      uint32_t h2 = hash(used[h + 1] & 0xffffff, r) % sz;
      if (h2 != h + 1) {
        return false;
      }
      used[h + 2] = used[h + 1];
    }
    used[h + 1] = rule;
  }
  return true;
}

static void emit_hash(size_t sz, uint32_t *used, uint32_t r) {
  printf("static const uint32_t fold_hash[%zu] = {\n", sz + 1);
  for (size_t i = 0; i <= sz; i++) {
    printf("0x%08x,\n", used[i]);
  }
  printf("};\n\n");
  printf("static uint32_t hashkey(uint32_t key) {\n");
  printf("  key ^= key >> 16;\n");
  printf("  key *= %u;\n", r);
  printf("  key ^= key >> 16;\n");
  printf("  key %%= %lu;\n", sz);
  printf("  return key;\n");
  printf("}\n");
}

static void find_hash(uint32_t *rules) {
  size_t rule_len = arrlen(rules);
  if (rule_len == 0) {
    fprintf(stderr, "Error: no fold rules found\n");
    abort();
  }

  uint32_t *used = malloc((rule_len * 2 + 1) * sizeof(uint32_t));
  if (!used) {
    abort();
  }

  for (size_t sz = rule_len | 1; sz < rule_len * 2; sz += 2) {
    for (uint32_t r = 0; r < 32 * 32; r++) {
      if (try_hash(used, rules, sz, r)) {
        emit_hash(sz, used, r);
        free(used);
        return;
      }
    }
  }

  free(used);
  fprintf(stderr, "Error: search for fold hash failed\n");
  abort();
}

int main(int argc, char *argv[]) {
  uint64_t cur_func = 0;

  if (argc != 2) {
    abort();
  }
  uint32_t *rules = nullptr;

  for (uint64_t i = 0; i < IR_INS_MAX; i++) {
    sh_put(name_to_insn, ir_names[i], i);
  }
  sh_put(name_to_insn, "_", FOLD_ARG_ANY);

  FILE *f = fopen(argv[1], "r");
  if (!f) {
    abort();
  }
  char *line = nullptr;
  size_t n = 0;
  printf("static fold_func_type fold_func_table[] = {\n");
  while (getline(&line, &n, f) != -1) {
    if ((0 == strncmp(line, "IRFOLD(", 7))) {
      auto c = &line[7];
      auto op = nexttoken(&c);
      auto left = nexttoken(&c);
      auto right = nexttoken(&c);
      uint32_t rule = cur_func << 24 | op << 16 | left << 8 | right;
      arrput(rules, rule);
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

  find_hash(rules);

  sh_free(name_to_insn);
  arrfree(rules);
  free(line);
}
