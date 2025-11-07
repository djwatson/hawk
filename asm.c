#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "asm.h"

#if defined(__APPLE__) && defined(__aarch64__)
#include <pthread.h>
#endif

static const size_t page_cnt = 250;
static const size_t msize = page_cnt * 4096;

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
  s->p--;
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
