#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "array.h"
#include "asm.h"

#if defined(__APPLE__) && defined(__aarch64__)
#include <pthread.h>
#endif

static const size_t page_cnt = 250;
static const size_t msize = page_cnt * 4096;

static int comment_sort(const void *a, const void *b) {
  const comment_entry *lhs = (const comment_entry *)a;
  const comment_entry *rhs = (const comment_entry *)b;
  if (lhs->offset < rhs->offset) {
    return -1;
  }
  if (lhs->offset > rhs->offset) {
    return 1;
  }
  return 0;
}

void emit_disassemble_all(emit_state *s) {
  if (!s || !s->p || !s->mtop) {
    return;
  }
  size_t len = (size_t)(s->mend - s->p);
  if (len == 0) {
    return;
  }

  comment_entry *comments = nullptr;
  size_t comment_cnt = arrlen(s->global_comments);
  if (comment_cnt) {
    for (size_t i = 0; i < comment_cnt; i++) {
      arrput(nullptr, comments, s->global_comments[i]);
    }
    qsort(comments, comment_cnt, sizeof(comment_entry), comment_sort);
  }

  printf("Full JIT disassembly (%zu bytes):\n", len);
  disassemble(s->p, len, comments);
}

int64_t emit_offset(emit_state *s) {
  assert(s);
  return (int64_t)s->p;
}

void emit_bind(emit_state *s, uint64_t label, uint64_t jmp) {
  (void)s;
  assert(jmp);
  assert(label);
  auto offset = (int32_t)((int64_t)label - (int64_t)jmp);
  memcpy((int32_t *)(jmp - 4), &offset, sizeof(int32_t));
}

void emit_advance(emit_state *s, int64_t offset) {
  assert(s);
  s->p -= offset;
}

void emit_check(emit_state *s) {
  assert(s);
  if (s->p - s->mtop <= 64) {
    printf("Fail: Out of jit memory\n");
    exit(-1);
  }
}

void emit_cleanup(emit_state *s) {
  assert(s);
  if (!s->mtop) {
    return;
  }

  if (s->const_pool) {
    for (size_t i = 0; i < arrlen(s->const_pool); i++) {
      arrfree(s->const_pool[i].patches);
    }
    arrfree(s->const_pool);
    s->const_pool = nullptr;
  }
  arrfree(s->comments);
  s->comments = nullptr;
  s->global_comments = nullptr;
  zone_free(&s->global_comment_zone);
  memset(&s->global_comment_zone, 0, sizeof(s->global_comment_zone));

  munmap(s->mtop, msize);
  s->mtop = nullptr;
  s->mend = nullptr;
  s->p = nullptr;
}

void emit_init(emit_state *s) {
  assert(s);
  if (s->mtop) {
    return;
  }

  memset(&s->z, 0, sizeof(s->z));
  memset(&s->global_comment_zone, 0, sizeof(s->global_comment_zone));
  s->comments = nullptr;
  s->global_comments = nullptr;
  s->alloc_slowpath = nullptr;

  auto prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  auto flags = MAP_PRIVATE | MAP_ANONYMOUS;
#if defined(__APPLE__) && defined(MAP_JIT)
  flags |= MAP_JIT;
#endif

  auto mem = mmap(nullptr, msize, prot, flags, -1, 0);
  if (mem == MAP_FAILED) {
    fprintf(stderr, "Fail: mmap(%zu bytes) for JIT arena: %s\n", msize,
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  s->mtop = (uint8_t *)mem;
  s->p = s->mtop + msize;
  s->mend = s->p;

  // Valgrind requires some readahead space.
  s->p -= 4;

  emit_init_slowpath(s);
}

void emit_writable_begin(emit_state *s) {
  (void)s;
#if defined(__APPLE__) && defined(__aarch64__)
  pthread_jit_write_protect_np(0);
#endif
}

void emit_writable_end(emit_state *s) {
  (void)s;
#if defined(__APPLE__) && defined(__aarch64__)
  pthread_jit_write_protect_np(1);
#endif
}

int add_constant(emit_state *s, double value) {
  assert(s);
  union {
    double d;
    uint64_t u;
  } target = {.d = value};
  size_t len = arrlen(s->const_pool);
  for (size_t i = 0; i < len; i++) {
    union {
      double d;
      uint64_t u;
    } existing = {.d = s->const_pool[i].value};
    if (existing.u == target.u) {
      return (int)i;
    }
  }
  constant_entry entry = {.value = value, .addr = nullptr, .patches = nullptr};
  arrput(&s->z, s->const_pool, entry);
  return (int)(arrlen(s->const_pool) - 1);
}

void load_constant(emit_state *s, int idx, uint8_t dst) {
  assert(s);
  assert(idx >= 0);
  assert((size_t)idx < arrlen(s->const_pool));
  asm_load_constant(s, idx, dst);
}

void emit_constant_pool(emit_state *s) {
  assert(s);
  size_t len = arrlen(s->const_pool);
  if (!len) {
    return;
  }

  uintptr_t aligned = (uintptr_t)s->p & ~(uintptr_t)0x7;
  s->p = (uint8_t *)aligned;

  for (size_t i = 0; i < len; i++) {
    s->p -= sizeof(double);
    memcpy(s->p, &s->const_pool[i].value, sizeof(double));
    s->const_pool[i].addr = s->p;
  }

  asm_patch_constant_pool(s);

  for (size_t i = 0; i < len; i++) {
    s->const_pool[i].patches = nullptr;
  }
  s->const_pool = nullptr;
}
