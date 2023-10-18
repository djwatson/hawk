// Copyright 2023 Dave Watson

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "defs.h"

typedef struct bcfunc bcfunc;
typedef struct {
  union {
    int64_t value;
    uint32_t *raddress;
    bcfunc *func;
    void *ptr;
  };
} gc_obj;

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
#define CHAR_TAG 0x0c
#define NIL_TAG 0x14
#define EOF_TAG 0x1c
#define UNDEFINED_TAG 0x24

#define NIL                                                                    \
  (gc_obj) { .value = NIL_TAG }
#define TRUE_REP                                                               \
  (gc_obj) { .value = 0x0104 }
#define FALSE_REP                                                              \
  (gc_obj) { .value = 0x0004 }
#define EOF_OBJ                                                                \
  (gc_obj) { .value = EOF_TAG }

#define IMMEDIATE_MASK 0xff

typedef struct flonum_s {
  uint32_t type;
  uint32_t rc;
  double x;
} flonum_s;

typedef struct string_s {
  uint32_t type;
  uint32_t rc;
  gc_obj len;
  char str[];
} string_s;

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
  gc_obj len;
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
  gc_obj len;
  gc_obj v[];
} closure_s;

typedef closure_s cont_s;

typedef struct port_s {
  uint32_t type;
  uint32_t rc;
  int64_t input_port;
  int64_t fd;
  FILE *file;
  gc_obj eof;
  uint64_t buf_pos;
  uint64_t buf_sz;
  char *in_buffer;
} port_s;

void print_obj(gc_obj obj, FILE *file);
gc_obj from_c_str(const char *s);
gc_obj equalp(gc_obj a, gc_obj b);

// GC interface:
INLINE size_t heap_object_size(void *obj);
typedef void (*trace_callback)(gc_obj *field, void *ctx);
INLINE void trace_heap_object(void *obj, trace_callback visit, void *ctx);

MAYBE_UNUSED static inline symbol *to_symbol(gc_obj obj) {
  return (symbol *)(obj.value - SYMBOL_TAG);
}
MAYBE_UNUSED static inline closure_s *to_closure(gc_obj obj) {
  return (closure_s *)(obj.value - CLOSURE_TAG);
}
MAYBE_UNUSED static inline cont_s *to_cont(gc_obj obj) {
  return (cont_s *)(obj.value - PTR_TAG);
}
// This one is not PTR, but anything!
MAYBE_UNUSED static inline void *to_raw_ptr(gc_obj obj) {
  return (void *)(obj.value & ~TAG_MASK);
}
MAYBE_UNUSED static inline string_s *to_string(gc_obj obj) {
  return (string_s *)(obj.value - PTR_TAG);
}
MAYBE_UNUSED static inline flonum_s *to_flonum(gc_obj obj) {
  return (flonum_s *)(obj.value - FLONUM_TAG);
}
MAYBE_UNUSED static inline int64_t to_fixnum(gc_obj obj) {
  return obj.value >> 3;
}
MAYBE_UNUSED static inline cons_s *to_cons(gc_obj obj) {
  return (cons_s *)(obj.value - CONS_TAG);
}
MAYBE_UNUSED static inline vector_s *to_vector(gc_obj obj) {
  return (vector_s *)(obj.value - VECTOR_TAG);
}
MAYBE_UNUSED static inline port_s *to_port(gc_obj obj) {
  return (port_s *)(obj.value - PTR_TAG);
}
MAYBE_UNUSED static inline char to_char(gc_obj obj) { return (obj.value >> 8); }
MAYBE_UNUSED static inline uint32_t *to_return_address(gc_obj obj) {
  return obj.raddress;
}
MAYBE_UNUSED static inline bcfunc *to_func(gc_obj obj) { return obj.func; }
MAYBE_UNUSED static inline bcfunc *closure_code_ptr(closure_s *clo) {
  return (bcfunc *)clo->v[0].value;
}
MAYBE_UNUSED static inline string_s *get_sym_name(symbol *s) {
  return (string_s *)(s->name.value - PTR_TAG);
}
MAYBE_UNUSED static inline gc_obj tag_sym(symbol *s) {
  return (gc_obj){((int64_t)s + SYMBOL_TAG)};
}
MAYBE_UNUSED static inline uint8_t get_tag(gc_obj obj) {
  return obj.value & TAG_MASK;
}
MAYBE_UNUSED static inline uint8_t get_imm_tag(gc_obj obj) {
  return obj.value & IMMEDIATE_MASK;
}
MAYBE_UNUSED static inline uint32_t get_ptr_tag(gc_obj obj) {
  return ((uint32_t *)(obj.value - PTR_TAG))[0];
}
MAYBE_UNUSED static inline bool is_char(gc_obj obj) {
  return get_imm_tag(obj) == CHAR_TAG;
}
MAYBE_UNUSED static inline bool is_closure(gc_obj obj) {
  return get_tag(obj) == CLOSURE_TAG;
}
MAYBE_UNUSED static inline bool is_cons(gc_obj obj) {
  return get_tag(obj) == CONS_TAG;
}
MAYBE_UNUSED static inline bool is_ptr(gc_obj obj) {
  return get_tag(obj) == PTR_TAG;
}
MAYBE_UNUSED static inline bool is_literal(gc_obj obj) {
  return get_tag(obj) == LITERAL_TAG;
}
MAYBE_UNUSED static inline bool is_string(gc_obj obj) {
  return is_ptr(obj) && get_ptr_tag(obj) == STRING_TAG;
}
MAYBE_UNUSED static inline bool is_undefined(gc_obj obj) {
  return get_imm_tag(obj) == UNDEFINED_TAG;
}
MAYBE_UNUSED static inline bool is_vector(gc_obj obj) {
  return get_tag(obj) == VECTOR_TAG;
}
MAYBE_UNUSED static inline bool is_flonum(gc_obj obj) {
  return get_tag(obj) == FLONUM_TAG;
}
MAYBE_UNUSED static inline bool is_fixnum(gc_obj obj) {
  return get_tag(obj) == FIXNUM_TAG;
}
MAYBE_UNUSED static inline bool is_fixnums(gc_obj a, gc_obj b) {
  return get_tag((gc_obj){a.value | b.value}) == FIXNUM_TAG;
}
MAYBE_UNUSED static inline gc_obj tag_fixnum(int64_t num) {
  assert(((num << 3) >> 3) == num);
  return (gc_obj){((uint64_t)num << 3)};
}
MAYBE_UNUSED static inline gc_obj tag_string(string_s *s) {
  return (gc_obj){((int64_t)s + PTR_TAG)};
}
MAYBE_UNUSED static inline gc_obj tag_symbol(symbol *s) {
  return (gc_obj){((int64_t)s + SYMBOL_TAG)};
}
MAYBE_UNUSED static inline gc_obj tag_flonum(flonum_s *s) {
  return (gc_obj){((int64_t)s + FLONUM_TAG)};
}
MAYBE_UNUSED static inline gc_obj tag_cons(cons_s *s) {
  return (gc_obj){((int64_t)s + CONS_TAG)};
}
MAYBE_UNUSED static inline gc_obj tag_vector(vector_s *s) {
  return (gc_obj){((int64_t)s + VECTOR_TAG)};
}
MAYBE_UNUSED static inline gc_obj tag_cont(closure_s *s) {
  return (gc_obj){((int64_t)s + PTR_TAG)};
}
MAYBE_UNUSED static inline gc_obj tag_closure(closure_s *s) {
  return (gc_obj){((int64_t)s + CLOSURE_TAG)};
}
MAYBE_UNUSED static inline gc_obj tag_port(port_s *s) {
  return (gc_obj){((int64_t)s + PTR_TAG)};
}
MAYBE_UNUSED static inline gc_obj tag_char(char ch) {
  return (gc_obj){(((int64_t)ch << 8) + CHAR_TAG)};
}
MAYBE_UNUSED static inline gc_obj tag_return_address(uint32_t *pc) {
  return (gc_obj){.raddress = pc};
}
MAYBE_UNUSED static inline gc_obj tag_func(bcfunc *func) {
  return (gc_obj){.func = func};
}
MAYBE_UNUSED static inline gc_obj tag_ptr(void *ptr) {
  return (gc_obj){.ptr = ptr};
}
MAYBE_UNUSED static inline gc_obj tag_void(void *ptr, uint8_t tag) {
  return (gc_obj){.value = (uintptr_t)ptr | tag};
}
#define RC_FIELD(obj) ((uint32_t *)obj)[1]
