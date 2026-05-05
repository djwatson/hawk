#define _DEFAULT_SOURCE

#include <sys/mman.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zstd.h>

#include "array.h"
#include "gc.h"
#include "hawk.h"
#include "profiler.h"
#include "types.h"
#include "vm.h"

typedef struct {
  uintptr_t mem;
  uintptr_t from_space;
  uintptr_t to_space;
  size_t size;
} gc_heap;

typedef struct {
  uintptr_t mem;
  size_t size;
} gc_nursery;

static gc_heap heap;
static gc_nursery nursery;
uintptr_t gc_hp;
uintptr_t gc_limit;
size_t soft_limit = 32UL << 20;
uintptr_t gc_soft_limit;
uintptr_t gc_nursery_start;
size_t gc_nursery_size;
gc_root_range gc_roots[GC_MAX_ROOTS];
size_t gc_roots_len;
static gc_scan_callback scan_callback;
static void *scan_data;
static gc_header **worklist;
static gc_obj **remembered_set;
static uintptr_t old_hp;
static uintptr_t old_limit;

typedef struct {
  bcfunc *ptr;
} pinned_func_entry;

static pinned_func_entry *pinned_funcs;

enum : uint64_t {
  FORWARD_TAG = UINT64_MAX,
  IMAGE_VERSION_RAW = 0,
  IMAGE_VERSION_ZSTD = 1,
};

enum : size_t { IMAGE_HEADER_SIZE = 28 };

typedef struct {
  uint64_t fwdtag;
  gc_header *fwd;
} gc_forward;

typedef enum {
  GC_YOUNG,
  GC_FULL,
} gc_collect_mode;

static gc_collect_mode collect_mode;

static uintptr_t align_size(uintptr_t size) {
  return (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
}

static uintptr_t old_space_size(void) { return heap.size / 2; }

static bool in_range(uintptr_t p, uintptr_t base, size_t size) {
  return p >= base && p < base + size;
}

static bool in_old_space(uintptr_t p, uintptr_t base) {
  return in_range(p, base, old_space_size());
}

static bool in_old_active(uintptr_t p) {
  return in_old_space(p, heap.to_space);
}

static bool in_old_from(uintptr_t p) {
  return in_old_space(p, heap.from_space);
}

static bool in_nursery(uintptr_t p) {
  return in_range(p, nursery.mem, nursery.size);
}

static bool is_forwarded(gc_header const *obj) {
  return ((gc_forward const *)obj)->fwdtag == FORWARD_TAG;
}

static gc_header *forwarded(gc_header const *obj) {
  return ((gc_forward const *)obj)->fwd;
}

static void forward_obj(gc_header *obj, gc_header *new_obj) {
  gc_forward *fwd = (gc_forward *)obj;
  fwd->fwd = new_obj;
  fwd->fwdtag = FORWARD_TAG;
}

static void scan_object(gc_header *obj);
NOINLINE static void gc_collect(void);

static void gc_insert_pinned_func(bcfunc *func) {
  uintptr_t target = (uintptr_t)func;
  size_t lo = 0;
  size_t hi = arrlen(pinned_funcs);
  while (lo < hi) {
    size_t mid = lo + ((hi - lo) >> 1);
    if ((uintptr_t)pinned_funcs[mid].ptr < target) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  arrput(pinned_funcs, ((pinned_func_entry){.ptr = func}));
  memmove(&pinned_funcs[lo + 1], &pinned_funcs[lo],
          (arrlen(pinned_funcs) - lo - 1) * sizeof(*pinned_funcs));
  pinned_funcs[lo].ptr = func;
}

static void reset_nursery(void) {
  gc_hp = nursery.mem + nursery.size;
  gc_limit = nursery.mem;
  gc_soft_limit = gc_hp - MIN(soft_limit, nursery.size);
}

static size_t nursery_used(void) {
  return (nursery.mem + nursery.size) - gc_hp;
}

static size_t old_bytes_used(void) {
  return (heap.to_space + old_space_size()) - old_hp;
}

static size_t old_bytes_free(void) { return old_hp - old_limit; }

static void *old_alloc(size_t sz) {
  sz = align_size(sz);
  uintptr_t new_hp = old_hp - sz;
  if (new_hp < old_limit) {
    fprintf(stderr, "out of old generation memory, increase GC_SPACE\n");
    abort();
  }
  old_hp = new_hp;
  return (void *)old_hp;
}

INLINE static void visit_field(gc_obj *slot, void *ctx) {
  (void)ctx;
  if (!is_heap_object(*slot)) {
    return;
  }
  gc_header *obj = to_gc_header(*slot);
  uintptr_t ptr = (uintptr_t)obj;
  if (ptr == 0) {
    return;
  }
  if (collect_mode == GC_YOUNG && !in_nursery(ptr)) {
    if (!in_old_active(ptr) && !is_func(*slot)) {
      abort();
    }
    return;
  }
  if (collect_mode == GC_FULL && !in_nursery(ptr) && !in_old_from(ptr)) {
    if (!in_old_active(ptr) && !is_func(*slot)) {
      abort();
    }
    return;
  }
  if (is_forwarded(obj)) {
    *slot = tag_header(forwarded(obj), get_tag(*slot));
    return;
  }
  size_t sz = align_size(heap_object_size(obj));
  if (obj->type == FUNC_TAG) {
    bcfunc *stable_func = malloc(sz);
    if (!stable_func) {
      fprintf(stderr, "out of memory during collection, increate GC_SPACE\n");
      abort();
    }
    memcpy(stable_func, obj, sz);
    forward_obj(obj, &stable_func->header);
    *slot = tag_header(stable_func, get_tag(*slot));
    gc_register_bcfunc(stable_func);
    arrput(worklist, &stable_func->header);
    return;
  }
  gc_header *copy = old_alloc(sz);
  memcpy(copy, obj, sz);
  forward_obj(obj, copy);
  *slot = tag_header(copy, get_tag(*slot));
  arrput(worklist, copy);
}

static void scan_root_range(const uint64_t *start, const uint64_t *end) {
  assert(start <= end);
  for (const uint64_t *p = start; p < end; p++) {
    visit_field((gc_obj *)p, nullptr);
  }
}

/* Some embedders store raw pointers in root slots (not gc_obj values).
 * Those slots cannot be passed directly to visit_field because the GC expects
 * tagged words. We temporarily add the tag, visit, then write back the raw
 * pointer so moved objects are reflected in the original slot. */
static void scan_ptr_root_range(const void *rootp, size_t len, uint8_t tag) {
  uintptr_t *slots = (uintptr_t *)rootp;
  for (size_t i = 0; i < len; i++) {
    if (slots[i] == 0) {
      continue;
    }
    gc_obj tagged = tag_header((gc_header *)slots[i], tag);
    visit_field(&tagged, nullptr);
    slots[i] = (uintptr_t)to_raw_ptr(tagged);
  }
}

static void gc_add_mark_root(const uint64_t *rootp, size_t len) {
  assert(rootp);
  assert(len != 0);
  scan_root_range(rootp, rootp + len);
}

static void flip_spaces(void) {
  // memset((void *)heap.from_space, 0, old_space_size());
  uintptr_t new_space = heap.from_space;
  heap.from_space = heap.to_space;
  heap.to_space = new_space;
  old_hp = heap.to_space + old_space_size();
  old_limit = heap.to_space;
}

static void scan_object(gc_header *obj) {
  trace_heap_object(obj, visit_field, nullptr);
}

NOINLINE static void gc_collect(void) {
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  profiler_set_in_gc(true);
  size_t old_soft = soft_limit;
  size_t old_before = old_bytes_used();
  size_t heap_before = old_bytes_used() + nursery_used();
  bool full = old_bytes_free() < nursery_used();
  collect_mode = full ? GC_FULL : GC_YOUNG;
  if (full) {
    flip_spaces();
  }
  arrlen_set(worklist, 0);

  for (size_t i = 0; i < gc_roots_len; i++) {
    gc_root_range root = gc_roots[i];
    if (root.tag != 0) {
      scan_ptr_root_range(root.ptr, root.len, root.tag);
    } else {
      gc_add_mark_root((const uint64_t *)root.ptr, root.len);
    }
  }
  if (!full) {
    arr_for_each(remembered_set, field) { visit_field(field, nullptr); }
  }
  arrlen_set(remembered_set, 0);

  if (scan_callback) {
    scan_callback(scan_data, gc_add_mark_root);
  }
  if (full) {
    arr_for_each(pinned_funcs, entry) { arrput(worklist, &entry.ptr->header); }
  }

  while (arrlen(worklist) > 0) {
    gc_header *obj = *arrlast(worklist);
    arrpop(worklist);
    scan_object(obj);
  }

  size_t old_used = old_bytes_used();
  if (old_soft <= SIZE_MAX / 2 && old_used > old_soft / 3) {
    soft_limit *= 3;
  }
  reset_nursery();
  size_t old_after = old_bytes_used();
  size_t heap_after = old_after + nursery_used();
  size_t promoted = old_after > old_before ? old_after - old_before : 0;
  size_t freed = old_soft > promoted ? old_soft - promoted : 0;
  struct timespec end;
  clock_gettime(CLOCK_MONOTONIC, &end);
  double elapsed_ms = (double)(end.tv_sec - start.tv_sec) * 1000.0 +
                      (double)(end.tv_nsec - start.tv_nsec) / 1000000.0;
  fprintf(stderr, "gc_collect(%s): %.3f ms, heap: %zu, freed: %zu, soft: %zu\n",
          full ? "F" : "N", elapsed_ms, heap_after / 1000000, freed / 1000000,
          soft_limit / 1000000);
  profiler_set_in_gc(false);
}

void gc_init(void) {
  size_t space_size = 4ULL << 30;
  char *heap_env = getenv("GC_SPACE");
  if (heap_env) {
    space_size = (size_t)atoll(heap_env);
  }
  auto mem = mmap(nullptr, space_size * 2, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
  if (mem == MAP_FAILED) {
    fprintf(stderr, "Heap allocation failed: %zu bytes\n", space_size * 2);
    abort();
  }
  auto nursery_mem = mmap(nullptr, space_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANON, -1, 0);
  if (nursery_mem == MAP_FAILED) {
    fprintf(stderr, "Nursery allocation failed: %zu bytes\n", space_size);
    abort();
  }
  heap.mem = (uintptr_t)mem;
  heap.to_space = (uintptr_t)mem;
  heap.from_space = (uintptr_t)mem + space_size;
  heap.size = space_size * 2;
  old_hp = heap.to_space + space_size;
  old_limit = heap.to_space;
  nursery.mem = (uintptr_t)nursery_mem;
  nursery.size = space_size;
  gc_nursery_start = nursery.mem;
  gc_nursery_size = nursery.size;
  reset_nursery();
}

NOINLINE void gc_log_slow(gc_obj *field) {
  if (in_nursery((uintptr_t)field)) {
    return;
  }
  arrput(remembered_set, field);
}

void gc_set_scan_callback(gc_scan_callback cb, void *data) {
  scan_callback = cb;
  scan_data = data;
}

void gc_register_bcfunc(bcfunc *func) {
  gc_insert_pinned_func(func);
  gc_log_slow(&func->name);
  gc_obj *consts = (gc_obj *)func->data;
  for (uint64_t i = 0; i < func->const_cnt; i++) {
    gc_log_slow(&consts[i]);
  }
}

void *gc_base_ptr(void *p) {
  uintptr_t target = (uintptr_t)p;
  size_t lo = 0;
  size_t hi = arrlen(pinned_funcs);
  while (lo < hi) {
    size_t mid = lo + ((hi - lo) >> 1);
    if ((uintptr_t)pinned_funcs[mid].ptr <= target) {
      lo = mid + 1;
    } else {
      hi = mid;
    }
  }
  if (lo == 0) {
    return nullptr;
  }
  bcfunc *func = pinned_funcs[lo - 1].ptr;
  uintptr_t start = (uintptr_t)func;
  uintptr_t end = start + heap_object_size(func);
  if (start <= target && target < end) {
    return func;
  }
  return nullptr;
}

void gc_free(void) {
  arrfree(remembered_set);
  arrfree(worklist);
  arr_for_each(pinned_funcs, entry) { free(entry.ptr); }
  arrfree(pinned_funcs);
  munmap((void *)heap.mem, heap.size);
  munmap((void *)nursery.mem, nursery.size);
}

typedef struct {
  uintptr_t base;
  size_t len;
  char const *path;
} image_ctx;

typedef struct {
  uint8_t *base;
  size_t len;
  char const *path;
  gc_header **worklist;
} dump_image_ctx;

static void read_image_fail(char const *path, char const *msg) {
  fprintf(stderr, "Failed to read image %s: %s\n", path, msg);
  abort();
}

static void dump_image_fail(char const *path, char const *msg) {
  fprintf(stderr, "Failed to write image %s: %s\n", path, msg);
  abort();
}

static void read_image_zstd_fail(char const *path, size_t code) {
  fprintf(stderr, "Failed to read image %s: zstd: %s\n", path,
          ZSTD_getErrorName(code));
  abort();
}

static void dump_image_zstd_fail(char const *path, size_t code) {
  fprintf(stderr, "Failed to write image %s: zstd: %s\n", path,
          ZSTD_getErrorName(code));
  abort();
}

static gc_header *dump_copy_object(gc_header *obj, dump_image_ctx *ctx) {
  if (is_forwarded(obj)) {
    return forwarded(obj);
  }
  size_t sz = align_size(heap_object_size(obj));
  if (ctx->len + sz > old_space_size()) {
    dump_image_fail(ctx->path, "image larger than GC semispace");
  }
  gc_header *copy = (gc_header *)(ctx->base + ctx->len);
  memcpy(copy, obj, sz);
  ctx->len += sz;
  forward_obj(obj, copy);
  arrput(ctx->worklist, copy);
  return copy;
}

static void dump_visit_field(gc_obj *slot, void *ctx) {
  if (!is_heap_object(*slot)) {
    return;
  }
  dump_image_ctx *image = ctx;
  gc_header *obj = to_gc_header(*slot);
  if (is_forwarded(obj)) {
    *slot = tag_header(forwarded(obj), get_tag(*slot));
    return;
  }
  uintptr_t ptr = (uintptr_t)obj;
  if (!in_old_active(ptr) && !in_nursery(ptr) && !is_func(*slot)) {
    abort();
  }
  gc_header *copy = dump_copy_object(obj, image);
  *slot = tag_header(copy, get_tag(*slot));
}

static void dump_rebase_field(gc_obj *slot, void *ctx) {
  if (!is_heap_object(*slot)) {
    return;
  }
  uint8_t *base = ctx;
  uintptr_t offset = (uintptr_t)to_raw_ptr(*slot) - (uintptr_t)base;
  *slot = (gc_obj){.value = (int64_t)offset + get_tag(*slot)};
}

static void rebase_image_field(gc_obj *slot, void *ctx) {
  if (!is_heap_object(*slot)) {
    return;
  }
  image_ctx const *image = ctx;
  uintptr_t offset = (uintptr_t)to_raw_ptr(*slot);
  if (offset >= image->len) {
    read_image_fail(image->path, "pointer offset out of bounds");
  }
  *slot = tag_header((gc_header *)(image->base + offset), get_tag(*slot));
}

gc_obj gc_read_image(uint8_t const *data, size_t data_len, char const *path) {
  if (data_len < IMAGE_HEADER_SIZE) {
    read_image_fail(path, "file too short");
  }

  if (memcmp(data, "HAWK", 4) != 0) {
    read_image_fail(path, "invalid magic");
  }

  uint64_t version;
  uint64_t image_len_u64;
  uint64_t start_u64;
  memcpy(&version, &data[4], sizeof(version));
  memcpy(&image_len_u64, &data[12], sizeof(image_len_u64));
  memcpy(&start_u64, &data[20], sizeof(start_u64));
  if (version != IMAGE_VERSION_RAW && version != IMAGE_VERSION_ZSTD) {
    read_image_fail(path, "unsupported version");
  }
  if (image_len_u64 > SIZE_MAX) {
    read_image_fail(path, "image too large");
  }
  size_t image_len = (size_t)image_len_u64;
  if (image_len > old_space_size()) {
    read_image_fail(path, "image larger than GC semispace");
  }
  uintptr_t image_base = heap.from_space;
  uint8_t const *payload = data + IMAGE_HEADER_SIZE;
  size_t payload_len = data_len - IMAGE_HEADER_SIZE;
  if (version == IMAGE_VERSION_RAW) {
    if (payload_len != image_len) {
      read_image_fail(path, "length mismatch");
    }
    memcpy((void *)image_base, payload, image_len);
  } else {
    size_t res =
        ZSTD_decompress((void *)image_base, image_len, payload, payload_len);
    if (ZSTD_isError(res)) {
      read_image_zstd_fail(path, res);
    }
    if (res != image_len) {
      read_image_fail(path, "decompressed length mismatch");
    }
  }

  image_ctx image = {.base = image_base, .len = image_len, .path = path};
  uintptr_t scan = image_base;
  uintptr_t end = image_base + image_len;

  while (scan < end) {
    gc_header *obj = (gc_header *)scan;
    size_t size = align_size(heap_object_size(obj));
    if (scan + size > end) {
      read_image_fail(path, "object extends beyond image");
    }
    trace_heap_object(obj, rebase_image_field, &image);
    scan += size;
  }
  if (scan != end) {
    read_image_fail(path, "image object walk did not end at boundary");
  }

  gc_obj start = {.value = (int64_t)start_u64};
  rebase_image_field(&start, &image);
  arrlen_set(worklist, 0);
  collect_mode = GC_FULL;
  visit_field(&start, nullptr);
  while (arrlen(worklist) > 0) {
    gc_header *obj = *arrlast(worklist);
    arrpop(worklist);
    scan_object(obj);
  }
  return start;
}

gc_obj gc_read_image_file(char const *path) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    perror("fopen");
    abort();
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    perror("fseek");
    abort();
  }
  long fsize = ftell(fp);
  if (fsize < 0) {
    perror("ftell");
    abort();
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    perror("fseek");
    abort();
  }
  if (fsize < (long)IMAGE_HEADER_SIZE) {
    read_image_fail(path, "file too short");
  }

  uint8_t *data = malloc((size_t)fsize);
  if (!data) {
    fprintf(stderr, "Failed to allocate %li bytes\n", fsize);
    abort();
  }
  if (fread(data, 1, (size_t)fsize, fp) != (size_t)fsize) {
    read_image_fail(path, "short read");
  }
  fclose(fp);
  gc_obj start = gc_read_image(data, (size_t)fsize, path);
  free(data);
  return start;
}

EXPORT void gc_dump_image_and_die(gc_obj clo, gc_obj path, gc_obj compress) {
  vm_trace_reset();
  if (!is_closure(clo)) {
    abort();
  }
  if (!is_string(path)) {
    abort();
  }
  if (!is_bool(compress)) {
    abort();
  }
  char const *filename = to_string(path)->str;
  uint8_t *data = malloc(old_space_size());
  if (!data) {
    dump_image_fail(filename, "out of memory");
  }

  dump_image_ctx image = {
      .base = data,
      .len = 0,
      .path = filename,
      .worklist = nullptr,
  };
  gc_obj root = clo;
  gc_obj start = to_closure(clo)->v[0];
  dump_visit_field(&root, &image);
  dump_visit_field(&start, &image);

  while (arrlen(image.worklist) > 0) {
    gc_header *obj = *arrlast(image.worklist);
    arrpop(image.worklist);
    trace_heap_object(obj, dump_visit_field, &image);
  }

  arr_for_each(pinned_funcs, entry) {
    if (is_forwarded(&entry.ptr->header)) {
      continue;
    }
    fprintf(stderr, "undumped pinned func: %s %p\n",
            to_string(entry.ptr->name)->str, (void *)entry.ptr);
  }

  uintptr_t scan = (uintptr_t)data;
  uintptr_t end = scan + image.len;
  while (scan < end) {
    gc_header *obj = (gc_header *)scan;
    trace_heap_object(obj, dump_rebase_field, data);
    scan += align_size(heap_object_size(obj));
  }
  dump_rebase_field(&root, data);
  dump_rebase_field(&start, data);
  bool do_compress = compress.value == TRUE_REP.value;
  uint8_t *payload = data;
  size_t payload_len = image.len;
  uint64_t version = IMAGE_VERSION_RAW;
  uint8_t *compressed = nullptr;
  if (do_compress) {
    size_t compressed_cap = ZSTD_compressBound(image.len);
    compressed = malloc(compressed_cap);
    if (!compressed) {
      dump_image_fail(filename, "out of memory");
    }
    size_t compressed_len =
        ZSTD_compress(compressed, compressed_cap, data, image.len, 19);
    if (ZSTD_isError(compressed_len)) {
      dump_image_zstd_fail(filename, compressed_len);
    }
    payload = compressed;
    payload_len = compressed_len;
    version = IMAGE_VERSION_ZSTD;
  }

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    perror("fopen");
    abort();
  }
  uint64_t image_len = image.len;
  uint64_t start_u64 = (uint64_t)start.value;
  if (fwrite("HAWK", 1, 4, fp) != 4 ||
      fwrite(&version, sizeof(version), 1, fp) != 1 ||
      fwrite(&image_len, sizeof(image_len), 1, fp) != 1 ||
      fwrite(&start_u64, sizeof(start_u64), 1, fp) != 1 ||
      fwrite(payload, 1, payload_len, fp) != payload_len || fclose(fp) != 0) {
    dump_image_fail(filename, "short write");
  }
  arrfree(image.worklist);
  free(compressed);
  free(data);
  exit(EXIT_SUCCESS);
}

NOINLINE void *gc_alloc_slow(uint64_t sz) {
  sz = align_size(sz);
  if (sz > nursery.size) {
    fprintf(stderr, "allocation %" PRIu64 " exceeds nursery size %zu\n", sz,
            nursery.size);
    abort();
  }
  gc_collect();
  uintptr_t new_hp = gc_hp - sz;
  if (new_hp < gc_limit) {
    fprintf(stderr, "out of memory %" PRIu64 "\n", sz);
    abort();
  }
  gc_hp = new_hp;
  return (void *)gc_hp;
}
