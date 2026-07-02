#define _DEFAULT_SOURCE

#include <sys/mman.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#include "gc.h"
#include "types.h"
#include "vm.h"

enum : uint64_t { IMAGE_VERSION = 2 };
enum : size_t { IMAGE_HEADER_SIZE = 44 };

typedef struct {
  uintptr_t base;
  size_t len;
} image_ctx;

static gc_header *copy_image_obj(gc_header *obj, image_ctx const *image);

static void fixup_image_field(gc_obj *field, void *ctx) {
  if (!is_heap_object(*field))
    return;
  image_ctx const *image = ctx;
  uintptr_t offset = (uintptr_t)to_raw_ptr(*field);
  if (offset >= image->len) {
    fprintf(stderr, "read_image: pointer offset %" PRIuPTR " out of bounds\n",
            offset);
    abort();
  }
  gc_header *copy = copy_image_obj((gc_header *)(image->base + offset), image);
  *field = tag_header(copy, get_tag(*field));
}

static gc_header *copy_image_obj(gc_header *obj, image_ctx const *image) {
  if (is_forwarded(obj)) {
    return forward_ptr(obj);
  }
  size_t sz = heap_align(heap_object_size(obj));
  if ((uintptr_t)obj + sz > image->base + image->len) {
    fprintf(stderr, "read_image: object extends beyond image\n");
    abort();
  }
  gc_header *copy = (gc_header *)gc_alloc_slow(sz);
  uint8_t alloc_flags = copy->flags;
  memcpy(copy, obj, sz);
  copy->rc = 0;
  copy->flags = alloc_flags & GC_LARGE;
  set_forward(obj, copy);
  if (copy->type == FUNC_TAG) {
    gc_register_bcfunc((bcfunc *)copy);
  }
  trace_heap_object(copy, copy->type, fixup_image_field, (void *)image);
  return copy;
}

static gc_obj loaded_error_symbol;
static bool loaded_error_symbol_rooted;

gc_obj gc_error_symbol(void) { return loaded_error_symbol; }

static bool has_zstd_suffix(char const *path) {
  size_t len = strlen(path);
  return len >= 5 && memcmp(path + len - 5, ".zstd", 5) == 0;
}

gc_obj gc_read_image(uint8_t const *data, size_t data_len, char const *path,
                     bool compressed) {
  LOG(gc, "image load");
  if (compressed) {
#ifdef HAVE_ZSTD
    unsigned long long len = ZSTD_getFrameContentSize(data, data_len);
    if (len == ZSTD_CONTENTSIZE_ERROR || len == ZSTD_CONTENTSIZE_UNKNOWN) {
      fprintf(stderr, "read_image: invalid zstd frame size\n");
      abort();
    }
    uint8_t *buf = malloc((size_t)len);
    if (!buf) {
      fprintf(stderr, "read_image: out of memory\n");
      abort();
    }
    size_t res = ZSTD_decompress(buf, (size_t)len, data, data_len);
    if (ZSTD_isError(res)) {
      fprintf(stderr, "read_image: zstd: %s\n", ZSTD_getErrorName(res));
      abort();
    }
    if (res != (size_t)len) {
      fprintf(stderr, "read_image: decompressed length mismatch\n");
      abort();
    }
    gc_obj result = gc_read_image(buf, res, path, false);
    free(buf);
    return result;
#else
    fprintf(stderr, "read_image: zstd support not compiled in\n");
    abort();
#endif
  }
  if (data_len < IMAGE_HEADER_SIZE) {
    fprintf(stderr, "read_image: file too short\n");
    abort();
  }
  if (memcmp(data, "HAWK", 4) != 0) {
    fprintf(stderr, "read_image: invalid magic\n");
    abort();
  }
  uint64_t version, gc_cnt_u64, image_len_u64, start_u64, error_u64;
  memcpy(&version, &data[4], sizeof(version));
  memcpy(&gc_cnt_u64, &data[12], sizeof(gc_cnt_u64));
  memcpy(&image_len_u64, &data[20], sizeof(image_len_u64));
  memcpy(&start_u64, &data[28], sizeof(start_u64));
  memcpy(&error_u64, &data[36], sizeof(error_u64));
  if (version != IMAGE_VERSION) {
    fprintf(stderr, "read_image: unsupported version\n");
    abort();
  }
  total_gc_cnt = gc_cnt_u64 + 1;
  size_t image_len = (size_t)image_len_u64;

  void *stage = mmap(nullptr, image_len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
  if (stage == MAP_FAILED) {
    fprintf(stderr, "read_image: failed to mmap staging\n");
    abort();
  }
  uintptr_t image_base = (uintptr_t)stage;

  uint8_t const *payload = data + IMAGE_HEADER_SIZE;
  size_t payload_len = data_len - IMAGE_HEADER_SIZE;
  if (payload_len != image_len) {
    fprintf(stderr, "read_image: length mismatch\n");
    abort();
  }
  memcpy((void *)image_base, payload, image_len);

  image_ctx image = {.base = image_base, .len = image_len};

  gc_obj start = {.value = (int64_t)start_u64};
  loaded_error_symbol = (gc_obj){.value = (int64_t)error_u64};

  // Trace from roots: rc 0→1, trace children, bump live_objects
  fixup_image_field(&start, &image);
  fixup_image_field(&loaded_error_symbol, &image);
  if (!loaded_error_symbol_rooted) {
    gc_add_root((const void *)&loaded_error_symbol, 1, 0);
    loaded_error_symbol_rooted = true;
  }
  gc_add_root(&start, 1, 0);
  LOG(gc, "image done");
  gc_collect();
  gc_remove_root(&start, 0);

  munmap(stage, image_len);
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
  bool compressed = has_zstd_suffix(path);
  if (!compressed && fsize < (long)IMAGE_HEADER_SIZE) {
    fprintf(stderr, "read_image_file: file too short\n");
    abort();
  }

  uint8_t *buf = malloc((size_t)fsize);
  if (!buf) {
    fprintf(stderr, "Failed to allocate %li bytes\n", fsize);
    abort();
  }
  if (fread(buf, 1, (size_t)fsize, fp) != (size_t)fsize) {
    fprintf(stderr, "read_image_file: short read\n");
    abort();
  }
  fclose(fp);
  gc_obj result = gc_read_image(buf, (size_t)fsize, path, compressed);
  free(buf);
  return result;
}

typedef struct {
  uint8_t *base;
  size_t len;
  gc_header **worklist;
} dump_ctx;

static gc_header *dump_copy_object(gc_header *obj, dump_ctx *ctx) {
  if (is_forwarded(obj)) {
    return (gc_header *)forward_ptr(obj);
  }
  size_t sz = heap_align(heap_object_size(obj));
  gc_header *copy = (gc_header *)(ctx->base + ctx->len);
  memcpy(copy, obj, sz);
  copy->flags = 0;
  copy->aux = 0;
  copy->rc = 0;
  ctx->len += sz;
  set_forward(obj, copy);
  arrput(ctx->worklist, copy);
  return copy;
}

static void dump_visit_field(gc_obj *field, void *ctx) {
  if (!is_heap_object(*field))
    return;
  dump_ctx *dc = ctx;
  gc_header *obj = to_gc_header(*field);
  if (is_forwarded(obj)) {
    *field = tag_header((gc_header *)forward_ptr(obj), get_tag(*field));
    return;
  }
  gc_header *copy = dump_copy_object(obj, dc);
  *field = tag_header(copy, get_tag(*field));
}

static void dump_rebase_field(gc_obj *field, void *ctx) {
  if (!is_heap_object(*field))
    return;
  uint8_t *base = ctx;
  uintptr_t offset = (uintptr_t)to_raw_ptr(*field) - (uintptr_t)base;
  *field = (gc_obj){.value = (int64_t)offset + get_tag(*field)};
}

void gc_dump_image(gc_obj clo, gc_obj path, gc_obj compress_level) {
  vm_trace_reset();
  if (!is_closure(clo)) {
    fprintf(stderr, "gc_dump_image: not a closure\n");
    abort();
  }
  if (!is_string(path)) {
    fprintf(stderr, "gc_dump_image: path not a string\n");
    abort();
  }

  char const *filename = to_string(path)->str;
  bool do_compress = compress_level.value != FALSE_REP.value;
#ifndef HAVE_ZSTD
  do_compress = false;
#endif
  int level = 0;
  if (do_compress) {
    level = (int)to_fixnum(compress_level);
  }

  uint8_t *data = malloc(gc_size);
  if (!data) {
    fprintf(stderr, "gc_dump_image: out of memory\n");
    abort();
  }

  dump_ctx dc = {.base = data, .len = 0, .worklist = nullptr};

  gc_obj root = clo;
  gc_obj start = to_closure(clo)->v[0];
  dump_visit_field(&root, &dc);
  dump_visit_field(&start, &dc);
  dump_visit_field(&loaded_error_symbol, &dc);

  while (arrlen(dc.worklist) > 0) {
    gc_header *obj = arrpop_last(dc.worklist);
    trace_heap_object(obj, obj->type, dump_visit_field, &dc);
  }

  // rebase to offsets
  uintptr_t scan = (uintptr_t)data;
  uintptr_t end = scan + dc.len;
  while (scan < end) {
    gc_header *obj = (gc_header *)scan;
    trace_heap_object(obj, obj->type, dump_rebase_field, data);
    scan += heap_align(heap_object_size(obj));
  }
  dump_rebase_field(&root, data);
  dump_rebase_field(&start, data);
  dump_rebase_field(&loaded_error_symbol, data);

  size_t file_len = IMAGE_HEADER_SIZE + dc.len;
  uint8_t *file = malloc(file_len);
  if (!file) {
    fprintf(stderr, "gc_dump_image: out of memory\n");
    abort();
  }
  uint64_t image_len = dc.len;
  uint64_t gc_cnt = total_gc_cnt;
  uint64_t start_u64 = (uint64_t)start.value;
  uint64_t error_u64 = (uint64_t)loaded_error_symbol.value;
  uint64_t version = IMAGE_VERSION;
  memcpy(file, "HAWK", 4);
  memcpy(&file[4], &version, sizeof(version));
  memcpy(&file[12], &gc_cnt, sizeof(gc_cnt));
  memcpy(&file[20], &image_len, sizeof(image_len));
  memcpy(&file[28], &start_u64, sizeof(start_u64));
  memcpy(&file[36], &error_u64, sizeof(error_u64));
  memcpy(file + IMAGE_HEADER_SIZE, data, dc.len);

  char *out_filename = nullptr;
  char const *write_filename = filename;
  uint8_t *payload = file;
  size_t payload_len = file_len;
  uint8_t *compressed = nullptr;
  if (do_compress) {
#ifdef HAVE_ZSTD
    size_t filename_len = strlen(filename);
    out_filename = malloc(filename_len + 6);
    if (!out_filename) {
      fprintf(stderr, "gc_dump_image: out of memory\n");
      abort();
    }
    memcpy(out_filename, filename, filename_len);
    memcpy(out_filename + filename_len, ".zstd", 6);
    write_filename = out_filename;
    size_t compressed_cap = ZSTD_compressBound(file_len);
    compressed = malloc(compressed_cap);
    if (!compressed) {
      fprintf(stderr, "gc_dump_image: out of memory\n");
      abort();
    }
    size_t compressed_len =
        ZSTD_compress(compressed, compressed_cap, file, file_len, level);
    if (ZSTD_isError(compressed_len)) {
      fprintf(stderr, "gc_dump_image: zstd: %s\n",
              ZSTD_getErrorName(compressed_len));
      abort();
    }
    payload = compressed;
    payload_len = compressed_len;
#endif
  }

  FILE *fp = fopen(write_filename, "wb");
  if (!fp) {
    perror("fopen");
    abort();
  }
  if (fwrite(payload, 1, payload_len, fp) != payload_len || fclose(fp) != 0) {
    fprintf(stderr, "gc_dump_image: write error\n");
    abort();
  }

  arrfree(dc.worklist);
  free(out_filename);
  free(compressed);
  free(file);
  free(data);
}

EXPORT void gc_dump_image_and_die(gc_obj clo, gc_obj path,
                                  gc_obj compress_level) {
  gc_dump_image(clo, path, compress_level);
  exit(EXIT_SUCCESS);
}
