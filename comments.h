// Copyright 2025 Dave Watson <dade.watson@gmail.com>
#pragma once

#include <stdint.h>

#include "zone_alloc.h"

typedef struct {
  int64_t offset;
  const char *text;
} comment_entry;

void comment_append(int64_t offset, zone *z, comment_entry **comments,
                    const char *fmt, ...);
