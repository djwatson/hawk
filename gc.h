#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "array.h"
#include "hawk.h"
#include "types.h"
#include "util/util.h"

typedef void (*gc_scan_root_cb)(const uint64_t *rootp, size_t len);
typedef void (*gc_scan_callback)(void *data, gc_scan_root_cb add_root);
struct bcfunc;
typedef struct {
  const void *ptr;
  size_t len;
  uint8_t tag;
} gc_root_range;

void gc_init(void);
enum { GC_MAX_ROOTS = 64 };

extern gc_root_range gc_roots[GC_MAX_ROOTS];
extern size_t gc_roots_len;
void gc_set_scan_callback(gc_scan_callback cb, void *data);
void gc_register_bcfunc(struct bcfunc *func);
void *gc_base_ptr(void *p);
gc_obj gc_read_image(uint8_t const *data, size_t len, char const *path,
                     bool compressed);
gc_obj gc_read_image_file(char const *path);
void gc_dump_image_and_die(gc_obj clo, gc_obj path, gc_obj compress_level);
NOINLINE void gc_log_slow(gc_obj *field);

static inline void gc_log(gc_obj *field) {
  MUSTTAIL return gc_log_slow(field);
}
void gc_free(void);

extern uintptr_t gc_hp;
extern uintptr_t gc_limit;
extern uintptr_t gc_soft_limit;
extern uintptr_t gc_nursery_start;
extern size_t gc_nursery_size;

NOINLINE void *gc_alloc_slow(uint64_t sz);

static inline void gc_add_root(const void *rootp, size_t len, uint8_t tag) {
  assert(gc_roots_len < GC_MAX_ROOTS);
  gc_roots[gc_roots_len++] = (gc_root_range){
      .ptr = rootp,
      .len = len,
      .tag = tag,
  };
}

static inline void gc_remove_root(const void *rootp, uint8_t tag) {
  assert(gc_roots_len > 0);
  size_t idx = gc_roots_len - 1;
  gc_root_range root = gc_roots[idx];
  assert(root.ptr == rootp && root.tag == tag);
  gc_roots_len = idx;
}

static inline void *gc_alloc(uint64_t sz) {
  assert((sz & 0x7) == 0);
  uintptr_t new_hp = gc_hp - sz;
  if (likely(new_hp >= gc_soft_limit)) {
    gc_hp = new_hp;
    return (void *)gc_hp;
  }
  MUSTTAIL return gc_alloc_slow(sz);
}
