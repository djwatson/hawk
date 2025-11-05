#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static uint8_t *mtop = nullptr;
static uint8_t *mend = nullptr;
uint8_t *p = nullptr;

static const size_t page_cnt = 4000;
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

void emit_cleanup() { munmap(mtop, msize); }

void emit_init() {
  if (mtop) {
    return;
  }

  mtop = mmap(nullptr, msize, PROT_READ | PROT_WRITE | PROT_EXEC,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  atexit(&emit_cleanup);
  assert(mtop);
  p = mtop + msize;
  mend = p;
}
