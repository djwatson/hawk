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
extern gc_root_range *gc_roots;
NOINLINE void gc_add_root_slow(const void *rootp, size_t len, uint8_t tag);
NOINLINE void gc_remove_root_slow(const void *rootp, uint8_t tag);
void gc_set_scan_callback(gc_scan_callback cb, void *data);
void gc_register_bcfunc(struct bcfunc *func);
void *gc_base_ptr(void *p);
gc_obj gc_read_image(uint8_t const *data, size_t len, char const *path);
gc_obj gc_read_image_file(char const *path);
void gc_dump_image_and_die(gc_obj clo, gc_obj path, gc_obj compress);
void gc_log(uint64_t a);
void gc_free(void);

extern uintptr_t gc_hp;
extern uintptr_t gc_limit;

NOINLINE void *gc_alloc_slow(uint64_t sz);

static inline void gc_add_root(const void *rootp, size_t len, uint8_t tag) {
  if (likely(gc_roots != nullptr &&
             arr_header(gc_roots)->length < arr_header(gc_roots)->capacity)) {
    size_t idx = arr_header(gc_roots)->length++;
    gc_roots[idx] = (gc_root_range){
        .ptr = rootp,
        .len = len,
        .tag = tag,
    };
    return;
  }
  MUSTTAIL return gc_add_root_slow(rootp, len, tag);
}

static inline void gc_remove_root(const void *rootp, uint8_t tag) {
  if (likely(gc_roots != nullptr && arr_header(gc_roots)->length > 0)) {
    size_t idx = arr_header(gc_roots)->length - 1;
    gc_root_range root = gc_roots[idx];
    if (likely(root.ptr == rootp && root.tag == tag)) {
      arrpop(gc_roots);
      return;
    }
  }
  MUSTTAIL return gc_remove_root_slow(rootp, tag);
}

static inline void *gc_alloc(uint64_t sz) {
  assert((sz & 0x7) == 0);
  uintptr_t new_hp = gc_hp - sz;
  if (likely(new_hp >= gc_limit)) {
    gc_hp = new_hp;
    return (void *)gc_hp;
  }
  MUSTTAIL return gc_alloc_slow(sz);
}
