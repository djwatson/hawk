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

static void emit_ensure_space(emit_state *s, size_t bytes) {
  assert(s);
  size_t available = (size_t)(s->mend - s->p);
  if (available < bytes) {
    printf("Fail: Out of jit memory\n");
    exit(EXIT_FAILURE);
  }
}

uint8_t *emit_byte(emit_state *s, uint8_t value) {
  emit_ensure_space(s, sizeof(uint8_t));
  uint8_t *out = s->p;
  *out = value;
  s->p += sizeof(uint8_t);
  return out;
}

uint8_t *emit_imm32(emit_state *s, uint32_t imm) {
  emit_ensure_space(s, sizeof(uint32_t));
  uint8_t *out = s->p;
  memcpy(out, &imm, sizeof(imm));
  s->p += sizeof(uint32_t);
  return out;
}

uint8_t *emit_imm64(emit_state *s, uint64_t imm) {
  emit_ensure_space(s, sizeof(uint64_t));
  uint8_t *out = s->p;
  memcpy(out, &imm, sizeof(imm));
  s->p += sizeof(uint64_t);
  return out;
}

int64_t emit_offset(emit_state *s) {
  assert(s);
  return (int64_t)s->p;
}

void label_add_patch(emit_state *s, label *label, enum label_patch_kind kind,
                     uint8_t *loc) {
  assert(s);
  assert(label);
  label_patch patch = {.kind = kind, .loc = loc};
  // Use heap-backed arrays so we can free after patching.
  arrput(nullptr, label->patches, patch);
}

void emit_label(emit_state *s, label *label) {
  assert(s);
  assert(label);
  assert(!label->emitted);
  label->emitted = true;
  label->addr = (uint8_t *)emit_offset(s);
  arr_for_each(label->patches, patch) {
    switch (patch.kind) {
    case LABEL_PATCH_JMP32:
      asm_patch_jmp32(s, patch.loc, label->addr);
      break;
    case LABEL_PATCH_JCC32:
      asm_patch_jcc32(s, patch.loc, label->addr);
      break;
    default:
      abort();
    }
  }
  if (label->patches) {
    arrfree(label->patches);
    label->patches = nullptr;
  }
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
  s->p += offset;
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
  s->comments = nullptr;
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
  s->mend = s->mtop + msize;
  s->p = s->mtop;

  // Valgrind requires some readahead space.
  s->p += 4;

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

  size_t pad = (size_t)((8 - ((uintptr_t)s->p & 7)) & 7);
  size_t needed = pad + len * sizeof(double);
  emit_ensure_space(s, needed);
  s->p += pad;

  for (size_t i = 0; i < len; i++) {
    memcpy(s->p, &s->const_pool[i].value, sizeof(double));
    s->const_pool[i].addr = s->p;
    s->p += sizeof(double);
  }

  asm_patch_constant_pool(s);

  for (size_t i = 0; i < len; i++) {
    s->const_pool[i].patches = nullptr;
  }
  s->const_pool = nullptr;
}
