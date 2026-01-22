// Copyright 2025 Dave Watson <dade.watson@gmail.com>

#include "comments.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "array.h"
#include "zone_alloc.h"

static char *zone_vsprintf(zone *z, const char *fmt, va_list args) {
  va_list measure;
  va_copy(measure, args);
  int needed = vsnprintf(nullptr, 0, fmt, measure);
  va_end(measure);
  if (needed < 0) {
    abort();
  }

  size_t bytes = (size_t)needed + 1;
  char *buf = zone_malloc(z, bytes);
  if (!buf) {
    abort();
  }

  va_list write_args;
  va_copy(write_args, args);
  int written = vsnprintf(buf, bytes, fmt, write_args);
  va_end(write_args);
  if (written < 0 || written >= (int)bytes) {
    abort();
  }
  return buf;
}

void comment_append(int64_t offset, zone *z, comment_entry **comments,
                    const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  char *msg = zone_vsprintf(z, fmt, args);
  va_end(args);
  comment_entry entry = {.offset = offset, .text = msg};
  arrput(z, *comments, entry);
}
