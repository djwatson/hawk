#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#if defined(__APPLE__) && defined(__aarch64__)
#include <pthread.h>
#endif

static uint8_t *mtop = nullptr;
static uint8_t *mend = nullptr;
uint8_t *p = nullptr;

static const size_t page_cnt = 250;
static const size_t msize = page_cnt * 4096;

int64_t emit_offset() { return (int64_t)p; }

void emit_bind(uint64_t label, uint64_t jmp) {
  assert(jmp);
  assert(label);
  auto offset = (int32_t)((int64_t)label - (int64_t)jmp);
  memcpy((int32_t *)(jmp - 4), &offset, sizeof(int32_t));
}

void emit_advance(int64_t offset) { p -= offset; }

void emit_check() {
  if (p - mtop <= 64) {
    printf("Fail: Out of jit memory\n");
    exit(-1);
  }
}

void emit_cleanup() {
  if (!mtop) {
    return;
  }

  munmap(mtop, msize);
  mtop = nullptr;
  mend = nullptr;
  p = nullptr;
}

void emit_init() {
  if (mtop) {
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

  atexit(&emit_cleanup);
  mtop = (uint8_t *)mem;
  p = mtop + msize;
  mend = p;

  // Valgrind requires some readahead space.
  p--;
}

void emit_writable_begin() {
#if defined(__APPLE__) && defined(__aarch64__)
  pthread_jit_write_protect_np(0);
#endif
}

void emit_writable_end() {
#if defined(__APPLE__) && defined(__aarch64__)
  pthread_jit_write_protect_np(1);
#endif
}
