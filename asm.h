#pragma once

#include <stdint.h>

typedef struct emit_state {
  uint8_t *mtop;
  uint8_t *mend;
  uint8_t *p;
} emit_state;

void emit_init(emit_state *s);
void emit_cleanup(emit_state *s);
int64_t emit_offset(emit_state *s);
void emit_advance(emit_state *s, int64_t offset);
void emit_bind(emit_state *s, uint64_t label, uint64_t jmp);
void emit_check(emit_state *s);
void emit_writable_begin(emit_state *s);
void emit_writable_end(emit_state *s);

#if defined(__aarch64__)
#include "asm_aarch64.h"
#elif defined(__x86_64__)
#include "asm_x64.h"
#else
#error "Unsupported architecture"
#endif
