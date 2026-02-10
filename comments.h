// Copyright 2025 Dave Watson <dade.watson@gmail.com>
#pragma once

#include <stdint.h>

typedef struct {
  int64_t offset;
  const char *text;
} comment_entry;

void comment_append(int64_t offset, comment_entry **comments, const char *fmt,
                    ...);
