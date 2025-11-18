#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "array.h"
#include "bc.h"
#include "gc.h"
#include "readbc.h"
#include "types.h"
#include "util/util.h"

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
static void reader_bytes(buffer_reader *reader, void *dst, size_t len);
static size_t pvarint_len(uint8_t prefix);
static uint64_t reader_pvarint(buffer_reader *reader);
static int64_t zigzag_decode(uint64_t value);
static void resolve_or_enqueue(heap_state *heap, size_t id, gc_obj *slot);
static gc_obj deserialize_constant(buffer_reader *reader, heap_state *heap);
static gc_obj deserialize_const_closure(buffer_reader *reader,
                                        heap_state *heap);
static gc_obj deserialize_string(buffer_reader *reader);
static gc_obj deserialize_symbol(buffer_reader *reader, heap_state *heap);
static gc_obj deserialize_function(buffer_reader *reader, heap_state *heap);

gc_obj heap_deserialize_from_file(char const *path) {
  heap_state out_heap;

  memset(&out_heap, 0, sizeof(out_heap));
  size_t file_size = 0;
  uint8_t *file_data = read_entire_file(path, &file_size);
  if (!file_data) {
    return FALSE_REP;
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
      return FALSE_REP;
    }
  }

  uint64_t version = reader_pvarint(&reader);
  if (version != 0) {
    fprintf(stderr, "Unsupported bytecode version: %llu\n",
            (unsigned long long)version);
    free(file_data);
    return FALSE_REP;
  }

  uint64_t const_count64 = reader_pvarint(&reader);
  if (const_count64 > SIZE_MAX) {
    fprintf(stderr, "Constant table too large\n");
    goto cleanup;
  }
  size_t const_count = (size_t)const_count64;

  // out_heap is on stack, so GC will save all out_heap.objects.
  out_heap.objects = gc_alloc(const_count * sizeof(gc_obj));
  memset(out_heap.objects, 0, const_count * sizeof(gc_obj));
  if (!out_heap.objects) {
    fprintf(stderr, "Out of memory allocating constant tables\n");
    goto cleanup;
  }
  out_heap.count = const_count;
  out_heap.current_id = const_count;
  out_heap.fixups = nullptr;

  for (size_t i = 0; i < const_count; i++) {
    size_t id = const_count - 1 - i;
    out_heap.current_id = id;
    gc_obj value = deserialize_constant(&reader, &out_heap);
    if (id >= out_heap.count) {
      fprintf(stderr, "Publishing invalid constant id %zu\n", id);
      goto cleanup;
    }
    out_heap.objects[id] = value;
  }

  if (arrlen(out_heap.fixups)) {
    printf("There are %li fixups\n", arrlen(out_heap.fixups));
  }
  for (size_t i = 0; i < arrlen(out_heap.fixups); i++) {
    fixup_entry entry = out_heap.fixups[i];
    if (entry.id >= out_heap.count) {
      fprintf(stderr, "Fixup references invalid id %zu\n", entry.id);
      goto cleanup;
    }
    *entry.slot = out_heap.objects[entry.id];
  }

  if (reader.pos != reader.size) {
    fprintf(stderr, "Trailing data remaining after deserialization\n");
    goto cleanup;
  }

cleanup:
  arrfree(out_heap.fixups);
  free(file_data);

  // all heap objects are no longer protected - only things reachable
  // from the initializer bcfunc will be kept (which is probably
  // everything, otherwise it wouldn't have been compiled!)
  return out_heap.objects[0];
}

static uint8_t *read_entire_file(char const *path, size_t *out_size) {
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    perror("fopen");
    return nullptr;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    perror("fseek");
    fclose(fp);
    return nullptr;
  }
  long sz = ftell(fp);
  if (sz < 0) {
    perror("ftell");
    fclose(fp);
    return nullptr;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    perror("fseek");
    fclose(fp);
    return nullptr;
  }
  uint8_t *buffer = malloc((size_t)sz);
  if (!buffer) {
    fprintf(stderr, "Failed to allocate %ld bytes\n", sz);
    fclose(fp);
    return nullptr;
  }
  if (sz > 0) {
    size_t read_bytes = fread(buffer, 1, (size_t)sz, fp);
    if (read_bytes != (size_t)sz) {
      fprintf(stderr, "Short read when loading bytecode\n");
      free(buffer);
      fclose(fp);
      return nullptr;
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

static void reader_bytes(buffer_reader *reader, void *dst, size_t len) {
  reader_require(reader, len);
  memcpy(dst, reader->data + reader->pos, len);
  reader->pos += len;
}

static size_t pvarint_len(uint8_t prefix) {
  return 1 + __builtin_ctz(((unsigned)prefix) | 0x100);
}

static uint64_t reader_pvarint(buffer_reader *reader) {
  uint8_t first = reader_u8(reader);
  size_t len = pvarint_len(first);
  if (len < 9) {
    uint8_t buf[9] = {0};
    buf[0] = first;
    if (len > 1) {
      reader_bytes(reader, buf + 1, len - 1);
    }
    uint64_t res = 0;
    memcpy(&res, buf, len);
    size_t unused = 64 - 8 * len;
    return (res << unused) >> (unused + len);
  }
  uint64_t value = 0;
  reader_bytes(reader, &value, 8);
  return value;
}

static int64_t zigzag_decode(uint64_t value) {
  return (int64_t)((value >> 1) ^ (uint64_t)-(int64_t)(value & 1));
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
  arrput(nullptr, heap->fixups, entry);
}

static gc_obj deserialize_constant(buffer_reader *reader, heap_state *heap) {
  uint64_t tag = reader_pvarint(reader);
  if (tag == STRING_TAG) {
    return deserialize_string(reader);
  }
  if (tag == SYMBOL_TAG) {
    return deserialize_symbol(reader, heap);
  }
  if (tag == FUNC_TAG) {
    return deserialize_function(reader, heap);
  }
  if (tag == CLOSURE_TAG) {
    return deserialize_const_closure(reader, heap);
  }
  int64_t decoded = zigzag_decode(tag);
  if ((decoded & TAG_MASK) != FIXNUM_TAG) {
    fprintf(stderr, "Unknown constant tag 0x%llx\n", (unsigned long long)tag);
    exit(EXIT_FAILURE);
  }
  return (gc_obj){.value = decoded};
}

static gc_obj deserialize_string(buffer_reader *reader) {
  uint64_t len_word = reader_pvarint(reader);
  gc_obj len_obj = {.value = (int64_t)len_word};
  int64_t len = to_fixnum(len_obj);
  if (len < 0) {
    fprintf(stderr, "Negative string length\n");
    exit(EXIT_FAILURE);
  }
  size_t bytes = (size_t)len;
  size_t alloc_size = sizeof(string_s) + bytes + 1;
  string_s *str = gc_alloc(align(alloc_size, sizeof(gc_obj)));
  str->header.type = STRING_TAG;
  str->len = tag_fixnum(bytes);
  reader_bytes(reader, str->str, bytes);
  str->str[bytes] = '\0';
  return tag_string(str);
}

static gc_obj deserialize_symbol(buffer_reader *reader, heap_state *heap) {
  uint64_t name_ref = reader_pvarint(reader);
  if ((name_ref & TAG_MASK) != PTR_TAG) {
    fprintf(stderr, "Expected pointer-tagged ID reference\n");
    exit(EXIT_FAILURE);
  }
  size_t name_id = (size_t)((name_ref - PTR_TAG) >> FIXNUM_SHIFT);
  symbol *sym = gc_alloc(sizeof(symbol));
  sym->header.type = SYMBOL_TAG;
  sym->val = DEAD;
  sym->opt = 0;
  sym->lst = nullptr;
  resolve_or_enqueue(heap, name_id, &sym->name);
  return tag_symbol(sym);
}

static gc_obj deserialize_const_closure(buffer_reader *reader,
                                        heap_state *heap) {
  uint64_t fun_ref = reader_pvarint(reader);
  if ((fun_ref & TAG_MASK) != CLOSURE_TAG) {
    fprintf(stderr, "Expected closure-tagged ID reference\n");
    exit(EXIT_FAILURE);
  }
  size_t fun_id = (size_t)((fun_ref - CLOSURE_TAG) >> FIXNUM_SHIFT);
  size_t slot_count = 1;
  closure_s *clo = gc_alloc(sizeof(closure_s) + slot_count * sizeof(gc_obj));
  clo->header.type = CLOSURE_TAG;
  clo->len = tag_fixnum((int64_t)slot_count);
  resolve_or_enqueue(heap, fun_id, &clo->v[0]);
  return tag_closure(clo);
}

static gc_obj deserialize_function(buffer_reader *reader, heap_state *heap) {
  uint64_t const_cnt64 = reader_pvarint(reader);
  if (const_cnt64 > SIZE_MAX) {
    fprintf(stderr, "Function constant table too large\n");
    exit(EXIT_FAILURE);
  }
  size_t const_cnt = (size_t)const_cnt64;

  uint64_t bc_cnt64 = reader_pvarint(reader);
  if (bc_cnt64 > SIZE_MAX) {
    fprintf(stderr, "Bytecode length too large\n");
    exit(EXIT_FAILURE);
  }
  size_t bc_cnt = (size_t)bc_cnt64;

  size_t payload_size =
      sizeof(bcfunc) + (const_cnt * sizeof(gc_obj)) + (bc_cnt * sizeof(bc));
  bcfunc *func = gc_alloc(align(payload_size, sizeof(gc_obj)));
  func->header.type = FUNC_TAG;
  func->name = DEAD;
  func->const_cnt = const_cnt;
  func->bc_cnt = bc_cnt;

  gc_obj *const_slots = (gc_obj *)func->data;
  bc *code = (bc *)(func->data + (const_cnt * sizeof(gc_obj)));

  for (size_t i = 0; i < const_cnt; i++) {
    uint64_t ref_id = reader_pvarint(reader);
    resolve_or_enqueue(heap, (size_t)ref_id, &const_slots[i]);
  }

  reader_bytes(reader, code, bc_cnt * sizeof(uint32_t));

  return tag_func(func);
}
