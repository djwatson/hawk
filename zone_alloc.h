// Copyright 2024 Dave Watson <dade.watson@gmail.com>

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct zone {
  uint8_t **regions;
  uint8_t *cur;
  uint8_t *end;
} zone;

enum : uint64_t {
  DEFAULT_SZ = 1024 * 10,
};

void *zone_malloc(zone *z, size_t sz);

void *zone_realloc(zone *z, void const *prev, size_t prev_size, size_t sz);

void zone_free(zone *z);
