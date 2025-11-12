#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
  int64_t offset;
  const char *text;
} comment_entry;

void disassemble(const uint8_t *code, size_t len,
                 const comment_entry *comments);
