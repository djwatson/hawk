#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "bc.h"
#include "bigint.h"
#include "hawk.h"

typedef struct bn bn_t;

typedef struct {
  union {
    int64_t value;
    bc *raddress;
    void *ptr;
  };
} gc_obj;

#define TAG_HEADER(ptr, tag)                                                   \
  ((gc_obj){.value = (int64_t)((intptr_t)(ptr) + (uint8_t)(tag))})
#define tag_header(ptr, tag) TAG_HEADER(ptr, tag)

#define FIXNUM_SHIFT 3
#define TAG_FIXNUM_VALUE(n) ((int64_t)(n) << FIXNUM_SHIFT)
#define TAG_FIXNUM_LITERAL(n) ((gc_obj){.value = TAG_FIXNUM_VALUE(n)})
static inline gc_obj tag_fixnum(int64_t n) {
  return (gc_obj){.value = TAG_FIXNUM_VALUE(n)};
}
#define tag_string(str) ((gc_obj){.value = (int64_t)(intptr_t)(str) + PTR_TAG})
#define tag_symbol(sym)                                                        \
  ((gc_obj){.value = (int64_t)(intptr_t)(sym) + SYMBOL_TAG})
#define tag_flonum(flonum)                                                     \
  ((gc_obj){.value = (int64_t)(intptr_t)(flonum) + FLONUM_TAG})
#define tag_cons(cons) ((gc_obj){.value = (int64_t)(intptr_t)(cons) + CONS_TAG})
#define tag_vector(vec)                                                        \
  ((gc_obj){.value = (int64_t)(intptr_t)(vec) + VECTOR_TAG})
#define tag_cont(cont) ((gc_obj){.value = (int64_t)(intptr_t)(cont) + PTR_TAG})
#define tag_closure(clo)                                                       \
  ((gc_obj){.value = (int64_t)(intptr_t)(clo) + CLOSURE_TAG})
#define tag_char(ch)                                                           \
  ((gc_obj){.value = ((int64_t)(uint8_t)(ch) << 8) + CHAR_TAG})
#define tag_return_address(pc) ((gc_obj){.raddress = (pc)})
#define tag_func(func) ((gc_obj){.value = (int64_t)(intptr_t)(func) + PTR_TAG})
#define tag_ptr(ptrval) ((gc_obj){.ptr = (ptrval)})
#define tag_void(ptrval, t)                                                    \
  ((gc_obj){.value = ((intptr_t)(ptrval) | ((uint8_t)(t) & TAG_MASK))})

typedef struct gc_header {
  uint8_t type;
  uint8_t flags;
  uint16_t aux;
  uint32_t rc;
} gc_header;
static_assert(sizeof(gc_header) == 8, "gc header is 8 bytes");

typedef struct bcfunc {
  gc_header header;
  uint32_t poly_cnt;
  uint32_t downrec_ok;
  gc_obj name;
  uint64_t const_cnt;
  uint64_t bc_cnt;
  // consts and bc are both pointers into data,
  // since we can have only a single flexible array member.
  // i.e. this is:
  // gc_obj[const_cnt];
  // bc[bc_cnt];
  uint8_t data[];
} bcfunc;

// X macros used so we can have string representations for
// pretty-printing debug info.

#define LOW_TAGS                                                               \
  X(FIXNUM, 0)                                                                 \
  X(PTR, 1)                                                                    \
  X(FLONUM, 2)                                                                 \
  X(CONS, 3)                                                                   \
  X(LITERAL, 4)                                                                \
  X(CLOSURE, 5)                                                                \
  X(SYMBOL, 6)                                                                 \
  X(VECTOR, 7)

// Object tags, use PTR_TAG on ptr, and OBJ_TAG in object itself as first
// field. Bottom three bits are '001' so it is also recognized as a PTR using
// the same tag.
#define PTR_TAGS                                                               \
  X(UNUSED1, 0x1)                                                              \
  X(STRING, 0x9)                                                               \
  X(FUNC, 0x11)                                                                \
  X(RATNUM, 0x19)                                                              \
  X(BOX, 0x21)                                                                 \
  X(CONT, 0x29)                                                                \
  X(RECORD, 0x31)                                                              \
  X(BIGNUM, 0x39)                                                              \
  X(COMPNUM, 0x41)                                                             \
  X(BYTEVECTOR, 0x49)                                                          \
  X(PORT, 0x51)                                                                \
  X(FLVECTOR, 0x61)

// Immediates.  Bottom three bits must be LITERAL_TAG.
// Uses bottom byte, and other 7 bytes used for storing literal.
#define IMMEDIATE_TAGS                                                         \
  X(BOOL, 0x4)                                                                 \
  X(CHAR, 0x0c)                                                                \
  X(NIL, 0x14)                                                                 \
  X(EOF, 0x1c)                                                                 \
  X(UNDEFINED, 0x24)                                                           \
  X(DEAD, 0x2c)                                                                \
  X(GUARD, 0x34)

extern char *low_tag_names[];
extern char *ptr_tag_names[];
extern char *immediate_tag_names[];

enum : uint8_t {
#define X(name, num) name##_TAG = (num),
  LOW_TAGS IMMEDIATE_TAGS PTR_TAGS
#undef X
      TAG_MASK = 0x7,
  IMMEDIATE_MASK = 0xff,
};

// PORT_TAG = 0x51 = 0101 0001 (bits 0,4,6)
// Available flag bits in lower byte: 1,2,3,5
// All PORT_TAG|flag combos fit in 7-bit ir_ins.type field (0-127)
typedef enum : uint32_t {
  PORT_INPUT = 1u << 1,  // bit 1
  PORT_OUTPUT = 1u << 2, // bit 2
  PORT_BINARY = 1u << 3, // bit 3
  PORT_CLOSED = 1u << 5, // bit 5
} port_flags;

// helper: bits that identify a PORT vs other PTR tags (bits 0,4,6)
#define PORT_IDENTITY ((uint32_t)PORT_TAG)

// Port flag bits that go in the header (INPUT|OUTPUT|BINARY|CLOSED).
// PORT_EOF, PORT_FILE, PORT_FOLD_CASE, PORT_NO_FOLD are stored in port_s
// fields.

#define NIL                                                                    \
  (gc_obj) { .value = NIL_TAG }
#define DEAD                                                                   \
  (gc_obj) { .value = DEAD_TAG }
#define UNDEFINED                                                              \
  (gc_obj) { .value = UNDEFINED_TAG }
#define TRUE_REP (gc_obj){.value = 0x0104}
#define FALSE_REP (gc_obj){.value = 0x0004}
#define EOF_OBJ                                                                \
  (gc_obj) { .value = EOF_TAG }

typedef struct flonum_s {
  gc_header header;
  double x;
} flonum_s;

typedef struct bignum_s {
  gc_header header;
  uint64_t placeholder;
} bignum_s;

typedef struct ratnum_s {
  gc_header header;
  gc_obj num;
  gc_obj denom;
} ratnum_s;

typedef struct compnum_s {
  gc_header header;
  gc_obj real;
  gc_obj imag;
} compnum_s;

typedef struct string_s {
  gc_header header;
  gc_obj len;
  char str[];
} string_s;

typedef struct symbol {
  gc_header header;
  gc_obj name; // string_s PTR_TAG'd value
  gc_obj val;
  int64_t opt;
  struct tv *lst;
} symbol;

typedef struct vector_s {
  gc_header header;
  gc_obj len;
  gc_obj v[];
} vector_s;

typedef struct flvector_s {
  gc_header header;
  gc_obj len;
  double v[];
} flvector_s;

typedef struct port_s {
  gc_header header;
  gc_obj fd;
  gc_obj open;
  gc_obj fold_case;
  gc_obj pos;
  gc_obj len;
  gc_obj cap;
  gc_obj buf;
  gc_obj sbuf;
} port_s;

typedef struct cons_s {
  gc_header header;
  gc_obj a;
  gc_obj b;
} cons_s;

typedef struct closure_s {
  gc_header header;
  gc_obj len;
  gc_obj v[];
} closure_s;

typedef closure_s cont_s;

// Type accessors
static inline gc_header *to_gc_header(gc_obj obj) {
  return (gc_header *)(obj.value & ~(int64_t)TAG_MASK);
}
static inline symbol *to_symbol(gc_obj obj) {
  return (symbol *)(obj.value - SYMBOL_TAG);
}
static inline closure_s *to_closure(gc_obj obj) {
  return (closure_s *)(obj.value - CLOSURE_TAG);
}
static inline cont_s *to_cont(gc_obj obj) {
  return (cont_s *)(obj.value - PTR_TAG);
}
static inline void *to_raw_ptr(gc_obj obj) {
  return (void *)(obj.value & ~(int64_t)TAG_MASK);
}
static inline string_s *to_string(gc_obj obj) {
  return (string_s *)(obj.value - PTR_TAG);
}
static inline flonum_s *to_flonum(gc_obj obj) {
  return (flonum_s *)(obj.value - FLONUM_TAG);
}
static inline int64_t to_fixnum(gc_obj obj) {
  return obj.value >> FIXNUM_SHIFT;
}
static inline cons_s *to_cons(gc_obj obj) {
  return (cons_s *)(obj.value - CONS_TAG);
}
static inline vector_s *to_vector(gc_obj obj) {
  return (vector_s *)(obj.value - VECTOR_TAG);
}
static inline flvector_s *to_flvector(gc_obj obj) {
  return (flvector_s *)(obj.value - PTR_TAG);
}
static inline port_s *to_port(gc_obj obj) {
  return (port_s *)(obj.value - PTR_TAG);
}
static inline char to_char(gc_obj obj) { return (char)(obj.value >> 8); }
static inline bc *to_return_address(gc_obj obj) { return obj.raddress; }
static inline bcfunc *to_func(gc_obj obj) {
  return (bcfunc *)(obj.value - PTR_TAG);
}
static inline bn_t *to_bignum(gc_obj obj) {
  return (bn_t *)(obj.value - PTR_TAG);
}
static inline ratnum_s *to_ratnum(gc_obj obj) {
  return (ratnum_s *)(obj.value - PTR_TAG);
}
static inline compnum_s *to_compnum(gc_obj obj) {
  return (compnum_s *)(obj.value - PTR_TAG);
}

static inline uint8_t get_tag(gc_obj obj) {
  return (uint8_t)(obj.value & TAG_MASK);
}
static inline uint8_t get_imm_tag(gc_obj obj) {
  return (uint8_t)(obj.value & IMMEDIATE_MASK);
}
static inline uint8_t get_ptr_tag(gc_obj obj) {
  return *(uint8_t *)(obj.value - PTR_TAG);
}

static inline bool is_char(gc_obj obj) { return get_imm_tag(obj) == CHAR_TAG; }
static inline bool is_closure(gc_obj obj) {
  return get_tag(obj) == CLOSURE_TAG;
}
static inline bool is_cons(gc_obj obj) { return get_tag(obj) == CONS_TAG; }
static inline bool is_ptr(gc_obj obj) { return get_tag(obj) == PTR_TAG; }
static inline bool is_literal(gc_obj obj) {
  return get_tag(obj) == LITERAL_TAG;
}
static inline bool is_bool(gc_obj obj) { return get_imm_tag(obj) == BOOL_TAG; }
static inline bool is_string(gc_obj obj) {
  return is_ptr(obj) && get_ptr_tag(obj) == STRING_TAG;
}
static inline bool is_bytevector(gc_obj obj) {
  return is_ptr(obj) && get_ptr_tag(obj) == BYTEVECTOR_TAG;
}
static inline string_s *to_bytevector(gc_obj obj) {
  return (string_s *)(obj.value - PTR_TAG);
}
static inline bool is_record(gc_obj obj) {
  return is_ptr(obj) && get_ptr_tag(obj) == RECORD_TAG;
}
static inline bool is_symbol(gc_obj obj) { return get_tag(obj) == SYMBOL_TAG; }
static inline bool is_undefined(gc_obj obj) {
  return get_imm_tag(obj) == UNDEFINED_TAG;
}
static inline uint8_t get_header_type(gc_obj obj) {
  return *(uint8_t *)(obj.value & ~(int64_t)TAG_MASK);
}
static inline bool is_vector(gc_obj obj) { return get_tag(obj) == VECTOR_TAG; }
static inline bool is_flvector(gc_obj obj) {
  return is_ptr(obj) && get_ptr_tag(obj) == FLVECTOR_TAG;
}
static inline bool is_port(gc_obj obj) {
  return is_ptr(obj) && (get_ptr_tag(obj) & PORT_IDENTITY) == PORT_IDENTITY;
}
static inline bool is_flonum(gc_obj obj) { return get_tag(obj) == FLONUM_TAG; }
static inline bool is_fixnum(gc_obj obj) { return get_tag(obj) == FIXNUM_TAG; }
static inline bool is_func(gc_obj obj) {
  return is_ptr(obj) && get_ptr_tag(obj) == FUNC_TAG;
}
static inline bool is_bignum(gc_obj obj) {
  return is_ptr(obj) && get_ptr_tag(obj) == BIGNUM_TAG;
}
static inline bool is_ratnum(gc_obj obj) {
  return is_ptr(obj) && get_ptr_tag(obj) == RATNUM_TAG;
}
static inline bool is_compnum(gc_obj obj) {
  return is_ptr(obj) && get_ptr_tag(obj) == COMPNUM_TAG;
}
static inline gc_obj tag_bignum(bn_t *bn) {
  return (gc_obj){.value = (int64_t)(intptr_t)bn + PTR_TAG};
}
static inline uint8_t get_type_tag(gc_obj obj) {
  if (is_ptr(obj)) {
    return *(uint8_t *)(obj.value - PTR_TAG);
  }
  if (is_literal(obj)) {
    return get_imm_tag(obj);
  }
  return get_tag(obj);
}
static inline bool is_heap_object(gc_obj obj) { return (obj.value & 3) != 0; }
static inline bool is_heap_tag(uint8_t tag) {
  return tag != FIXNUM_TAG && tag != LITERAL_TAG;
}

static inline size_t heap_align(size_t size) {
  return (size + sizeof(gc_obj) - 1) & ~(sizeof(gc_obj) - 1);
}

bcfunc const *closure_code_ptr(closure_s const *clo);
string_s *get_sym_name(symbol *s);
typedef void (*trace_callback)(gc_obj *obj, void *ctx);
const char *type_tag_name(uint8_t tag);
void print_type_tag(FILE *file, uint8_t tag);
void print_obj(gc_obj obj, FILE *file);

// Unfortunately, these somewhat large functions are pretty essential to inline
// in the GC.

INLINE static inline size_t heap_object_size(void *obj) {
  auto type = *(uint8_t *)obj;
  if ((type & PORT_IDENTITY) == PORT_IDENTITY) {
    return sizeof(port_s);
  }
  switch (type) {
  case FLONUM_TAG:
    return sizeof(flonum_s);
  case BIGNUM_TAG: {
    auto bn = (bn_t *)obj;
    return heap_align(sizeof(bn_t) + (size_t)bn->alloc * sizeof(uint64_t));
  }
  case RATNUM_TAG:
    return sizeof(ratnum_s);
  case COMPNUM_TAG:
    return sizeof(compnum_s);
  case STRING_TAG:
  case BYTEVECTOR_TAG: {
    auto str = (string_s *)obj;
    return heap_align(sizeof(string_s) + (size_t)to_fixnum(str->len) + 1);
  }
  case FLVECTOR_TAG: {
    auto vec = (flvector_s *)obj;
    return sizeof(flvector_s) + (size_t)to_fixnum(vec->len) * sizeof(double);
  }
  case SYMBOL_TAG:
    return sizeof(symbol);
  case CONT_TAG:
  case RECORD_TAG:
  case VECTOR_TAG: {
    auto vec = (vector_s *)obj;
    return sizeof(vector_s) + (size_t)to_fixnum(vec->len) * sizeof(gc_obj);
  }
  case CONS_TAG:
    return sizeof(cons_s);
  case CLOSURE_TAG: {
    auto clo = (closure_s *)obj;
    return sizeof(closure_s) + (size_t)to_fixnum(clo->len) * sizeof(gc_obj);
  }
  case FUNC_TAG: {
    auto func = (bcfunc *)obj;
    return heap_align(sizeof(bcfunc) + (func->const_cnt * sizeof(gc_obj)) +
                      (func->bc_cnt * sizeof(bc)));
  }
  default:
    printf("Unknown heap object size: %" PRIu8 " (0x%" PRIx8 ")\n", type, type);
    abort();
  }
}

static inline void trace_gc_obj_array(gc_obj *objs, uint64_t len,
                                      trace_callback visit, void *ctx) {
  for (uint64_t i = len; i > 0; i--) {
    visit(&objs[i - 1], ctx);
  }
}

INLINE static inline void trace_heap_object(gc_header *obj,
                                            trace_callback visit, void *ctx) {
  auto type = obj->type;
  if ((type & PORT_IDENTITY) == PORT_IDENTITY) {
    auto p = (port_s *)obj;
    trace_gc_obj_array(&p->fd, 8, visit, ctx);
    return;
  }
  switch (type) {
  case FLONUM_TAG:
  case BIGNUM_TAG:
  case STRING_TAG:
  case BYTEVECTOR_TAG:
    return;
  case FLVECTOR_TAG:
    return;
  case RATNUM_TAG: {
    auto rat = (ratnum_s *)obj;
    visit(&rat->num, ctx);
    visit(&rat->denom, ctx);
    return;
  }
  case COMPNUM_TAG: {
    auto cmp = (compnum_s *)obj;
    visit(&cmp->real, ctx);
    visit(&cmp->imag, ctx);
    return;
  }
  case SYMBOL_TAG: {
    auto sym = (symbol *)obj;
    visit(&sym->name, ctx);
    visit(&sym->val, ctx);
    return;
  }
  case CONT_TAG:
  case RECORD_TAG:
  case VECTOR_TAG: {
    auto vec = (vector_s *)obj;
    trace_gc_obj_array(vec->v, (uint64_t)to_fixnum(vec->len), visit, ctx);
    return;
  }
  case CONS_TAG: {
    auto cons = (cons_s *)obj;
    visit(&cons->b, ctx);
    visit(&cons->a, ctx);
    return;
  }
  case CLOSURE_TAG: {
    auto clo = (closure_s *)obj;
    trace_gc_obj_array(clo->v, (uint64_t)to_fixnum(clo->len), visit, ctx);
    return;
  }
  case FUNC_TAG: {
    auto func = (bcfunc *)obj;
    visit(&func->name, ctx);
    trace_gc_obj_array((gc_obj *)func->data, func->const_cnt, visit, ctx);
    return;
  }
  default:
    printf("Unknown heap object: %" PRIu8 " (0x%" PRIx8 ")\n", type, type);
    abort();
  }
}
