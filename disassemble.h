#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct {
  int64_t offset;
  const char *text;
} comment_entry;

void comment_append(int64_t offset, comment_entry **comments, const char *fmt,
                    ...);

void disassemble(const uint8_t *code, size_t len,
                 const comment_entry *comments);
