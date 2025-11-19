#pragma once

#include "disassemble.h"
#include "zone_alloc.h"
#include <stdint.h>
#include <stdbool.h> // For bool type

#define MAX_REG 64

typedef struct {
  uint8_t *inst0;
  uint8_t *inst1;
} const_patch;

typedef struct {
  double value;
  uint8_t *addr;
  const_patch *patches;
} constant_entry;

typedef struct {
  uint16_t s;
  bool used;
} regmap;

typedef struct emit_state {
  uint8_t *mtop;
  uint8_t *mend;
  uint8_t *p;
  zone z;
  comment_entry *comments;
  regmap regs[MAX_REG];
  uint32_t next_spill;
  constant_entry *const_pool;
} emit_state;

#if defined(__aarch64__)
#include "asm_aarch64.h"
#elif defined(__x86_64__)
#include "asm_x64.h"
#else
#error "Unsupported architecture"
#endif

void emit_init(emit_state *s);
void emit_cleanup(emit_state *s);
int64_t emit_offset(emit_state *s);
void emit_advance(emit_state *s, int64_t offset);
void emit_bind(emit_state *s, uint64_t label, uint64_t jmp);
void emit_check(emit_state *s);
void emit_writable_begin(emit_state *s);
void emit_writable_end(emit_state *s);
int add_constant(emit_state *s, double value);
void load_constant(emit_state *s, int idx, uint8_t dst);
void emit_constant_pool(emit_state *s);
