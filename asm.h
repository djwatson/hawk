#pragma once

#include "disassemble.h"
#include <stdbool.h> // For bool type
#include <stdint.h>

#define MAX_REG 64

typedef struct {
  uint8_t *inst0;
  uint8_t *inst1;
} const_patch;

enum label_patch_kind { LABEL_PATCH_JMP32, LABEL_PATCH_JCC32 };

typedef struct label_patch {
  enum label_patch_kind kind;
  uint8_t *loc;
} label_patch;

typedef struct label {
  uint8_t *addr;
  label_patch *patches;
  bool emitted;
} label;

typedef struct {
  double value;
  uint8_t *addr;
  const_patch *patches;
} constant_entry;

typedef struct emit_state {
  uint8_t *mtop;
  uint8_t *mend;
  uint8_t *p;
  comment_entry *comments;
  constant_entry *const_pool;
  uint8_t *alloc_slowpath;
} emit_state;

#if defined(__aarch64__)
#include "asm_aarch64.h"
#elif defined(__x86_64__)
#include "asm_x64.h"
#else
#error "Unsupported architecture"
#endif

void emit_init(emit_state *s);
void emit_init_slowpath(emit_state *s);
void emit_cleanup(emit_state *s);
int64_t emit_offset(emit_state *s);
void emit_advance(emit_state *s, int64_t offset);
void emit_bind(emit_state *s, uint64_t label, uint64_t jmp);
uint8_t *emit_byte(emit_state *s, uint8_t value);
uint8_t *emit_imm32(emit_state *s, uint32_t imm);
uint8_t *emit_imm64(emit_state *s, uint64_t imm);
void emit_writable_begin(emit_state *s);
void emit_writable_end(emit_state *s);
int add_constant(emit_state *s, double value);
void load_constant(emit_state *s, int idx, uint8_t dst);
void emit_constant_pool(emit_state *s);
void label_add_patch(emit_state *s, label *label, enum label_patch_kind kind,
                     uint8_t *loc);

static inline void asm_init_unallocatable_regs(bool used[MAX_REG]) {
#define X(name, unallocatable, callee_saved)                                   \
  if (unallocatable) {                                                         \
    used[name] = true;                                                         \
  }
  ASM_REGISTER_LIST(X)
  ASM_FREGISTER_LIST(X)
#undef X
}
