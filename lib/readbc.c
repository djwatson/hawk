#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "bc.h"
#include "types.h"

typedef struct {
  uint8_t *data;
  size_t size;
  size_t pos;
} buffer_reader;

typedef struct {
  size_t id;
  gc_obj *slot;
} fixup_entry;

typedef struct {
  gc_obj *objects;
  fixup_entry *fixups;
  size_t count;
  size_t current_id;
} heap_state;

static uint8_t *read_entire_file(char const *path, size_t *out_size);
static void reader_require(buffer_reader *reader, size_t bytes);
static uint8_t reader_u8(buffer_reader *reader);
static uint32_t reader_u32(buffer_reader *reader);
static uint64_t reader_u64(buffer_reader *reader);
static void reader_bytes(buffer_reader *reader, void *dst, size_t len);
static void *gc_alloc(size_t size);
static int64_t decode_fixnum(uint64_t value);
static size_t decode_ptr_id(uint64_t value);
static void resolve_or_enqueue(heap_state *heap, size_t id, gc_obj *slot);
static void publish_const(heap_state *heap, size_t id, gc_obj value);
static void fulfill_fixups(heap_state *heap, size_t id, gc_obj value);
static gc_obj deserialize_constant(buffer_reader *reader, heap_state *heap);
static gc_obj deserialize_string(buffer_reader *reader);
static gc_obj deserialize_symbol(buffer_reader *reader, heap_state *heap);
static gc_obj deserialize_function(buffer_reader *reader, heap_state *heap);

bool heap_deserialize_from_file(char const *path, heap_state *out_heap) {
  if (!out_heap) {
    return false;
  }
  memset(out_heap, 0, sizeof(*out_heap));
  size_t file_size = 0;
  uint8_t *file_data = read_entire_file(path, &file_size);
  if (!file_data) {
    return false;
  }

  buffer_reader reader = {
      .data = file_data,
      .size = file_size,
      .pos = 0,
  };

  const char expected_magic[] = "HAWK";
  for (size_t i = 0; i < sizeof(expected_magic) - 1; i++) {
    if (reader_u8(&reader) != (uint8_t)expected_magic[i]) {
      fprintf(stderr, "Invalid bytecode magic\n");
      free(file_data);
      return false;
    }
  }

  uint8_t version = reader_u8(&reader);
  if (version != 0) {
    fprintf(stderr, "Unsupported bytecode version: %u\n", version);
    free(file_data);
    return false;
  }

  uint32_t const_count32 = reader_u32(&reader);
  size_t const_count = (size_t)const_count32;

  bool ok = false;

  out_heap->objects = calloc(const_count ? const_count : 1, sizeof(gc_obj));
  if (!out_heap->objects) {
    fprintf(stderr, "Out of memory allocating constant tables\n");
    goto cleanup;
  }
  out_heap->count = const_count;
  out_heap->current_id = const_count;
  out_heap->fixups = NULL;

  for (size_t i = 0; i < const_count; i++) {
    size_t id = const_count - 1 - i;
    out_heap->current_id = id;
    gc_obj value = deserialize_constant(&reader, out_heap);
    publish_const(out_heap, id, value);
  }

  if (arrlen(out_heap->fixups) != 0) {
    fprintf(stderr, "Unresolved fixups after deserialization\n");
    goto cleanup;
  }

  if (reader.pos != reader.size) {
    fprintf(stderr, "Trailing data remaining after deserialization\n");
    goto cleanup;
  }

  ok = true;

cleanup:
  arrfree(out_heap->fixups);
  free(file_data);
  if (!ok) {
    free(out_heap->objects);
    memset(out_heap, 0, sizeof(*out_heap));
  }
  return ok;
}

static uint8_t *read_entire_file(char const *path, size_t *out_size) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    perror("fopen");
    return NULL;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    perror("fseek");
    fclose(fp);
    return NULL;
  }
  long sz = ftell(fp);
  if (sz < 0) {
    perror("ftell");
    fclose(fp);
    return NULL;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    perror("fseek");
    fclose(fp);
    return NULL;
  }
  uint8_t *buffer = malloc((size_t)sz);
  if (!buffer) {
    fprintf(stderr, "Failed to allocate %ld bytes\n", sz);
    fclose(fp);
    return NULL;
  }
  if (sz > 0) {
    size_t read_bytes = fread(buffer, 1, (size_t)sz, fp);
    if (read_bytes != (size_t)sz) {
      fprintf(stderr, "Short read when loading bytecode\n");
      free(buffer);
      fclose(fp);
      return NULL;
    }
  }
  fclose(fp);
  if (out_size) {
    *out_size = (size_t)sz;
  }
  return buffer;
}

static void reader_require(buffer_reader *reader, size_t bytes) {
  if (reader->pos + bytes > reader->size) {
    fprintf(stderr, "Unexpected end of bytecode stream\n");
    exit(EXIT_FAILURE);
  }
}

static uint8_t reader_u8(buffer_reader *reader) {
  reader_require(reader, 1);
  return reader->data[reader->pos++];
}

static uint32_t reader_u32(buffer_reader *reader) {
  reader_require(reader, 4);
  uint32_t v = 0;
  for (int i = 0; i < 4; i++) {
    v |= (uint32_t)reader->data[reader->pos + i] << (8u * i);
  }
  reader->pos += 4;
  return v;
}

static uint64_t reader_u64(buffer_reader *reader) {
  reader_require(reader, 8);
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) {
    v |= (uint64_t)reader->data[reader->pos + i] << (8u * i);
  }
  reader->pos += 8;
  return v;
}

static void reader_bytes(buffer_reader *reader, void *dst, size_t len) {
  reader_require(reader, len);
  memcpy(dst, reader->data + reader->pos, len);
  reader->pos += len;
}

static void *gc_alloc(size_t size) {
  void *ptr = malloc(size);
  if (!ptr) {
    fprintf(stderr, "gc_alloc failed for %zu bytes\n", size);
    exit(EXIT_FAILURE);
  }
  memset(ptr, 0, size);
  return ptr;
}

static int64_t decode_fixnum(uint64_t value) {
  if ((value & TAG_MASK) != FIXNUM_TAG) {
    fprintf(stderr, "Expected fixnum tagged value\n");
    exit(EXIT_FAILURE);
  }
  return (int64_t)value >> FIXNUM_SHIFT;
}

static size_t decode_ptr_id(uint64_t value) {
  if ((value & TAG_MASK) != PTR_TAG) {
    fprintf(stderr, "Expected pointer-tagged ID reference\n");
    exit(EXIT_FAILURE);
  }
  return (size_t)((value - PTR_TAG) >> FIXNUM_SHIFT);
}

static void resolve_or_enqueue(heap_state *heap, size_t dep_id, gc_obj *slot) {
  if (dep_id >= heap->count) {
    fprintf(stderr, "Reference to invalid constant id %zu\n", dep_id);
    exit(EXIT_FAILURE);
  }
  if (dep_id > heap->current_id) {
    *slot = heap->objects[dep_id];
    return;
  }
  fixup_entry entry = {
      .id = dep_id,
      .slot = slot,
  };
  arrput(NULL, heap->fixups, entry);
}

static void publish_const(heap_state *heap, size_t id, gc_obj value) {
  if (id >= heap->count) {
    fprintf(stderr, "Publishing invalid constant id %zu\n", id);
    exit(EXIT_FAILURE);
  }
  heap->objects[id] = value;
  fulfill_fixups(heap, id, value);
}

static void fulfill_fixups(heap_state *heap, size_t id, gc_obj value) {
  for (size_t i = 0; i < arrlen(heap->fixups);) {
    if (heap->fixups[i].id == id) {
      *heap->fixups[i].slot = value;
      size_t last = arrlen(heap->fixups) - 1;
      heap->fixups[i] = heap->fixups[last];
      arrpop(heap->fixups);
      continue;
    }
    i++;
  }
}

static gc_obj deserialize_constant(buffer_reader *reader, heap_state *heap) {
  uint64_t tag = reader_u64(reader);
  if (tag == STRING_TAG) {
    return deserialize_string(reader);
  }
  if (tag == SYMBOL_TAG) {
    return deserialize_symbol(reader, heap);
  }
  if (tag == FUNC_TAG) {
    return deserialize_function(reader, heap);
  }
  return (gc_obj){.value = (int64_t)tag};
}

static gc_obj deserialize_string(buffer_reader *reader) {
  uint64_t len_word = reader_u64(reader);
  int64_t len = decode_fixnum(len_word);
  if (len < 0) {
    fprintf(stderr, "Negative string length\n");
    exit(EXIT_FAILURE);
  }
  size_t bytes = (size_t)len;
  size_t alloc_size = sizeof(string_s) + bytes + 1;
  string_s *str = gc_alloc(alloc_size);
  str->header.type = STRING_TAG;
  str->len = tag_fixnum(bytes);
  reader_bytes(reader, str->str, bytes);
  str->str[bytes] = '\0';
  return tag_string(str);
}

static gc_obj deserialize_symbol(buffer_reader *reader, heap_state *heap) {
  uint64_t name_ref = reader_u64(reader);
  size_t name_id = decode_ptr_id(name_ref);
  symbol *sym = gc_alloc(sizeof(symbol));
  sym->header.type = SYMBOL_TAG;
  sym->val = UNDEFINED;
  sym->opt = 0;
  sym->lst = NULL;
  resolve_or_enqueue(heap, name_id, &sym->name);
  return tag_symbol(sym);
}

static gc_obj deserialize_function(buffer_reader *reader, heap_state *heap) {
  uint64_t const_cnt64 = reader_u64(reader);
  if (const_cnt64 > SIZE_MAX) {
    fprintf(stderr, "Function constant table too large\n");
    exit(EXIT_FAILURE);
  }
  size_t const_cnt = (size_t)const_cnt64;

  size_t *const_ids = NULL;
  if (const_cnt > 0) {
    const_ids = malloc(const_cnt * sizeof(size_t));
    if (!const_ids) {
      fprintf(stderr, "Out of memory storing function const ids\n");
      exit(EXIT_FAILURE);
    }
  }
  for (size_t i = 0; i < const_cnt; i++) {
    uint64_t ref_id = reader_u64(reader);
    const_ids[i] = (size_t)ref_id;
  }

  uint32_t bc_cnt32 = reader_u32(reader);
  size_t bc_cnt = (size_t)bc_cnt32;

  size_t payload_size =
      sizeof(bcfunc) + (const_cnt * sizeof(gc_obj)) + (bc_cnt * sizeof(bc));
  bcfunc *func = gc_alloc(payload_size);
  func->header.type = FUNC_TAG;
  func->name = UNDEFINED;
  func->const_cnt = const_cnt;
  func->bc_cnt = bc_cnt;

  gc_obj *const_slots = (gc_obj *)func->data;
  bc *code = (bc *)(func->data + const_cnt * sizeof(gc_obj));

  for (size_t i = 0; i < const_cnt; i++) {
    resolve_or_enqueue(heap, const_ids[i], &const_slots[i]);
  }
  free(const_ids);

  for (size_t i = 0; i < bc_cnt; i++) {
    uint32_t word = reader_u32(reader);
    code[i].full_data = word;
  }

  return tag_func(func);
}
