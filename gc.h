#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "array.h"
#include "hawk.h"
#include "types.h"
#include "util/util.h"

typedef void (*gc_scan_root_cb)(uint64_t *rootp, size_t len);
typedef void (*gc_scan_callback)(void *data, gc_scan_root_cb add_root);
struct bcfunc;
typedef struct {
  const void *ptr;
  size_t len;
  uint8_t tag;
} gc_root_range;

void gc_init(void);
enum { GC_MAX_ROOTS = 64 };

enum : uint8_t {
  GC_LOGGED = 1 << 0,
  GC_STICKY_LOGGED = 1 << 1,
  GC_FWD_TAG = 1 << 2,
  GC_LARGE = 1 << 3,
};

extern gc_root_range gc_roots[GC_MAX_ROOTS];
extern size_t gc_roots_len;
void gc_set_scan_callback(gc_scan_callback cb, void *data);
void gc_set_stack_root(gc_obj *bottom, gc_obj **top, gc_obj *end);
gc_obj gc_error_symbol(void);
void *gc_base_ptr(void *p);
void gc_register_bcfunc(struct bcfunc *func);
gc_obj gc_read_image(uint8_t const *data, size_t len, char const *path,
                     bool compressed);
gc_obj gc_read_image_file(char const *path);
void gc_dump_image(gc_obj clo, gc_obj path, gc_obj compress_level);
void gc_dump_image_and_die(gc_obj clo, gc_obj path, gc_obj compress_level);
NOINLINE void gc_log_slow(gc_obj obj);
extern uintptr_t gc_nursery_start;
extern size_t gc_nursery_size;

static inline void gc_log(gc_obj obj) {
  gc_header *hdr = to_gc_header(obj);
  uintptr_t addr = (uintptr_t)hdr;
  if (likely((hdr->flags & GC_LOGGED) ||
             addr < gc_nursery_start + gc_nursery_size))
    return;
  MUSTTAIL return gc_log_slow(obj);
}
void gc_free(void);

extern uintptr_t gc_hp;
extern uintptr_t gc_hp_end;
extern size_t gc_size;
extern uint64_t total_gc_cnt;
void gc_collect(void);

static inline void set_forward(gc_header *hdr, void *ptr) {
  hdr->flags |= GC_FWD_TAG;
  *(void **)(hdr + 1) = ptr;
}
static inline bool is_forwarded(gc_header *hdr) {
  return hdr->flags & GC_FWD_TAG;
}
static inline void *forward_ptr(gc_header *hdr) { return *(void **)(hdr + 1); }

NOINLINE void *gc_alloc_slow(uint64_t sz);
void *gc_alloc_old(uint64_t sz);

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
  if (likely(new_hp >= gc_hp_end)) {
    gc_hp = new_hp;
    *(uint64_t *)gc_hp = 0;
    return (void *)gc_hp;
  }
  MUSTTAIL return gc_alloc_slow(sz);
}
