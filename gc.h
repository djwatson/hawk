#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "util/util.h"

typedef void (*gc_scan_root_cb)(const uint64_t *rootp, size_t len);
typedef void (*gc_scan_callback)(void *data, gc_scan_root_cb add_root);
struct bcfunc;

void gc_init(void);
void gc_add_root(const uint64_t *rootp, size_t len);
void gc_remove_root(uint64_t const *rootp);
void gc_set_scan_callback(gc_scan_callback cb, void *data);
void gc_register_bcfunc(struct bcfunc *func);
void *gc_base_ptr(void *p);
void gc_log(uint64_t a);
void gc_free(void);

NOINLINE void *gc_alloc_slow(uint64_t sz);

static inline void *gc_alloc(uint64_t sz) {
  assert((sz & 0x7) == 0);
  return gc_alloc_slow(sz);
}
