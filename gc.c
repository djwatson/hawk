#define _DEFAULT_SOURCE

#include <sys/mman.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static gc_heap heap;
uintptr_t gc_hp;
uintptr_t gc_limit;
size_t soft_limit = 32UL << 20;
uintptr_t gc_soft_limit;
gc_root_range gc_roots[GC_MAX_ROOTS];
size_t gc_roots_len;
static gc_scan_callback scan_callback;
static void *scan_data;
static gc_header **worklist;

typedef struct {
  bcfunc *ptr;
} pinned_func_entry;

static pinned_func_entry *pinned_funcs;

enum : uint64_t {
  FORWARD_TAG = UINT64_MAX,
  IMAGE_VERSION_RAW = 0,
  IMAGE_VERSION_ZSTD = 1,
};

enum : size_t {
  IMAGE_HEADER_SIZE = 28,
};

typedef struct {
  uint64_t fwdtag;
  gc_header *fwd;
} gc_forward;

static uintptr_t align_size(uintptr_t size) {
  return (size + sizeof(uintptr_t) - 1) & ~(sizeof(uintptr_t) - 1);
}

static uintptr_t space_size(void) { return heap.size / 2; }

static bool in_space(uintptr_t p, uintptr_t base) {
  return p >= base && p < base + space_size();
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

INLINE static void visit_field(gc_obj *slot, void *ctx) {
  (void)ctx;
  if (!is_heap_object(*slot)) {
    return;
  }
  gc_header *obj = to_gc_header(*slot);
  if (!in_space((uintptr_t)obj, heap.from_space)) {
    if (!is_func(*slot)) {
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
  uintptr_t new_hp = gc_hp - sz;
  if (new_hp < gc_limit) {
    fprintf(stderr, "out of memory during collection, increate GC_SPACE\n");
    abort();
  }
  gc_hp = new_hp;
  gc_header *copy = (gc_header *)gc_hp;
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
  // memset((void *)heap.from_space, 0, space_size());
  uintptr_t new_space = heap.from_space;
  heap.from_space = heap.to_space;
  heap.to_space = new_space;
  gc_hp = heap.to_space + space_size();
  gc_limit = heap.to_space;
}

static size_t soft_bytes_copied(void) {
  return (heap.to_space + space_size()) - gc_hp;
}

static void update_soft_limit(void) {
  gc_soft_limit = gc_hp - gc_limit > soft_limit ? gc_hp - soft_limit : gc_limit;
}

static void scan_object(gc_header *obj) {
  trace_heap_object(obj, visit_field, nullptr);
}

static void gc_collect(void) {
  profiler_set_in_gc(true);
  size_t old_soft = soft_limit;
  flip_spaces();
  arrlen_set(worklist, 0);

  for (size_t i = 0; i < gc_roots_len; i++) {
    gc_root_range root = gc_roots[i];
    if (root.tag != 0) {
      scan_ptr_root_range(root.ptr, root.len, root.tag);
    } else {
      gc_add_mark_root((const uint64_t *)root.ptr, root.len);
    }
  }
  if (scan_callback) {
    scan_callback(scan_data, gc_add_mark_root);
  }
  arr_for_each(pinned_funcs, entry) { arrput(worklist, &entry.ptr->header); }

  while (arrlen(worklist) > 0) {
    gc_header *obj = *arrlast(worklist);
    arrpop(worklist);
    scan_object(obj);
  }

  size_t copied = soft_bytes_copied();
  if (old_soft <= SIZE_MAX / 2 && copied > old_soft / 3) {
    soft_limit *= 3;
  }
  if (verbose) {
    fprintf(stderr, "gc_collect(copied: %li, new soft:%li)\n", copied,
            soft_limit);
  }
  profiler_set_in_gc(false);
  update_soft_limit();
}

void gc_init(void) {
  size_t heap_size = 4ULL << 30;
  char *heap_env = getenv("GC_SPACE");
  if (heap_env) {
    heap_size = (size_t)atoll(heap_env);
  }
  auto mem = mmap(nullptr, heap_size * 2, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
  if (mem == MAP_FAILED) {
    fprintf(stderr, "Heap allocation failed: %zu bytes\n", heap_size * 2);
    abort();
  }
  heap.mem = (uintptr_t)mem;
  heap.to_space = (uintptr_t)mem;
  heap.from_space = (uintptr_t)mem + heap_size;
  gc_hp = (uintptr_t)mem + heap_size;
  gc_limit = (uintptr_t)mem;
  update_soft_limit();
  heap.size = heap_size * 2;
}

void gc_set_scan_callback(gc_scan_callback cb, void *data) {
  scan_callback = cb;
  scan_data = data;
}

void gc_register_bcfunc(bcfunc *func) { gc_insert_pinned_func(func); }

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

void gc_log(uint64_t a) {
  (void)a;
  abort();
}

void gc_free(void) {
  arrfree(worklist);
  arr_for_each(pinned_funcs, entry) { free(entry.ptr); }
  arrfree(pinned_funcs);
  munmap((void *)heap.mem, heap.size);
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
  if (ctx->len + sz > space_size()) {
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
  if (!in_space((uintptr_t)obj, heap.to_space) && !is_func(*slot)) {
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
  if (image_len > space_size()) {
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
  uint8_t *data = malloc(space_size());
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
  gc_collect();
  uintptr_t new_hp = gc_hp - align_size(sz);
  if (new_hp < gc_limit) {
    fprintf(stderr, "out of memory %" PRIu64 "\n", sz);
    abort();
  }
  gc_hp = new_hp;
  return (void *)gc_hp;
}
