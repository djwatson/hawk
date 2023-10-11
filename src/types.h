// Copyright 2023 Dave Watson

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

typedef struct bcfunc bcfunc;
typedef int64_t gc_obj;

// GC hack:

// All types are 8-byte aligned, except the return PC, which is
// 4-byte, and stored on the stack.  As long as it looks like an
// immediate type, we're ok.  So make sure tags 0x0 and 0x4 are
// immediate types.

#define FIXNUM_TAG 0x0
#define PTR_TAG 0x1
#define FLONUM_TAG 0x2
#define CONS_TAG 0x3
#define LITERAL_TAG 0x4
#define CLOSURE_TAG 0x5
#define SYMBOL_TAG 0x6
#define VECTOR_TAG 0x7

#define TAG_MASK 0x7

// Object tags, use PTR_TAG on ptr, and OBJ_TAG in object itself as first field.
// Bottom three bits are '001' so it is also recognized as a PTR using the same
// tag.
#define STRING_TAG 0x9
#define PORT_TAG 0x19
#define BOX_TAG 0x21
#define CONT_TAG 0x29
#define INPUT_PORT_TAG 0x0119

// Immediates.  Bottom three bits must be LITERAL_TAG.
// Uses bottom byte, and other 7 bytes used for storing literal.
#define BOOL_TAG 0x04
#define TRUE_REP 0x0104
#define FALSE_REP 0x0004
#define CHAR_TAG 0x0c
#define NIL_TAG 0x14
#define EOF_TAG 0x1c
#define UNDEFINED_TAG 0x24

#define IMMEDIATE_MASK 0xff

typedef struct flonum_s {
  uint32_t type;
  uint32_t rc;
  double x;
} flonum_s;

typedef struct string_s {
  uint32_t type;
  uint32_t rc;
  uint64_t len;
  char str[];
} string_s;

struct tv {
  uint16_t key;
};
typedef struct symbol {
  uint32_t type;
  uint32_t rc;
  gc_obj name; // string_s PTR_TAG'd value
  gc_obj val;
  int64_t opt;
  struct tv *lst;
} symbol;

typedef struct vector_s {
  uint32_t type;
  uint32_t rc;
  uint64_t len;
  gc_obj v[];
} vector_s;

typedef struct cons_s {
  uint32_t type;
  uint32_t rc;
  gc_obj a;
  gc_obj b;
} cons_s;

typedef struct closure_s {
  uint32_t type;
  uint32_t rc;
  uint64_t len;
  gc_obj v[];
} closure_s;

typedef struct port_s {
  uint32_t type;
  uint32_t rc;
  int64_t input_port;
  int64_t fd;
  FILE *file;
  uint64_t eof;
  uint64_t buf_pos;
  uint64_t buf_sz;
  char *in_buffer;
} port_s;

void print_obj(gc_obj obj, FILE *file);
gc_obj from_c_str(const char *s);
gc_obj equalp(gc_obj a, gc_obj b);

// GC interface:
size_t heap_object_size(void *obj);
typedef void (*trace_callback)(gc_obj *field, void *ctx);
void trace_heap_object(void *obj, trace_callback visit, void *ctx);

static inline symbol *to_symbol(gc_obj obj) {
  return (symbol *)(obj - SYMBOL_TAG);
}
static inline closure_s *to_closure(gc_obj obj) {
  return (closure_s *)(obj - CLOSURE_TAG);
}
static inline string_s *to_string(gc_obj obj) {
  return (string_s *)(obj - PTR_TAG);
}
static inline flonum_s *to_flonum(gc_obj obj) {
  return (flonum_s *)(obj - FLONUM_TAG);
}
static inline cons_s *to_cons(gc_obj obj) {
  return (cons_s *)(obj - CONS_TAG);
}
static inline vector_s *to_vector(gc_obj obj) {
  return (vector_s *)(obj - VECTOR_TAG);
}
static inline char to_char(gc_obj obj) { return (obj >> 8); }
static inline bcfunc *closure_code_ptr(closure_s *clo) {
  return (bcfunc *)clo->v[0];
}
static inline string_s *get_sym_name(symbol *s) {
  return (string_s *)(s->name - PTR_TAG);
}
static inline gc_obj tag_sym(symbol *s) {
  return (gc_obj)((int64_t)s + SYMBOL_TAG);
}
static inline uint8_t get_tag(gc_obj obj) { return obj & TAG_MASK; }
static inline uint8_t get_imm_tag(gc_obj obj) { return obj & IMMEDIATE_MASK; }
static inline uint32_t get_ptr_tag(gc_obj obj) {
  return ((uint32_t *)(obj - PTR_TAG))[0];
}
static inline bool is_char(gc_obj obj) {
  return get_imm_tag(obj) == CHAR_TAG;
}
static inline bool is_closure(gc_obj obj) {
  return get_tag(obj) == CLOSURE_TAG;
}
static inline bool is_cons(gc_obj obj) {
  return get_tag(obj) == CONS_TAG;
}
static inline bool is_ptr(gc_obj obj) {
  return get_tag(obj) == PTR_TAG;
}
static inline bool is_vector(gc_obj obj) {
  return get_tag(obj) == VECTOR_TAG;
}
static inline bool is_flonum(gc_obj obj) {
  return get_tag(obj) == FLONUM_TAG;
}
static inline gc_obj tag_string(string_s *s) {
  return (gc_obj)((int64_t)s + PTR_TAG);
}
static inline gc_obj tag_symbol(symbol *s) {
  return (gc_obj)((int64_t)s + SYMBOL_TAG);
}
static inline gc_obj tag_flonum(flonum_s *s) {
  return (gc_obj)((int64_t)s + FLONUM_TAG);
}
static inline gc_obj tag_cons(cons_s *s) {
  return (gc_obj)((int64_t)s + CONS_TAG);
}
static inline gc_obj tag_vector(vector_s *s) {
  return (gc_obj)((int64_t)s + VECTOR_TAG);
}
static inline gc_obj tag_closure(closure_s *s) {
  return (gc_obj)((int64_t)s + CLOSURE_TAG);
}
