#pragma once

void emit_init();
void emit_cleanup();
int64_t emit_offset();
void emit_advance(int64_t offset);
void emit_bind(uint64_t label, uint64_t jmp);
void emit_check();
void emit_writable_begin();
void emit_writable_end();

extern uint8_t *p;

#if defined(__aarch64__)
#include "asm_aarch64.h"
#elif defined(__x86_64__)
#include "asm_x64.h"
#else
#error "Unsupported architecture"
#endif
