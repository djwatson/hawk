#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "bc.h"
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
  union {
    uint64_t type;
    uint64_t fwdtag;
  };
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
  X(COMPNUM, 0x41)

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
static inline uint32_t get_ptr_tag(gc_obj obj) {
  return ((uint32_t *)(obj.value - PTR_TAG))[0];
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
static inline bool is_record(gc_obj obj) {
  return is_ptr(obj) && get_ptr_tag(obj) == RECORD_TAG;
}
static inline bool is_symbol(gc_obj obj) { return get_tag(obj) == SYMBOL_TAG; }
static inline bool is_undefined(gc_obj obj) {
  return get_imm_tag(obj) == UNDEFINED_TAG;
}
static inline bool is_vector(gc_obj obj) { return get_tag(obj) == VECTOR_TAG; }
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
static inline uint32_t get_type_tag(gc_obj obj) {
  if (is_ptr(obj)) {
    return ((uint32_t *)(obj.value - PTR_TAG))[0];
  }
  if (is_literal(obj)) {
    return get_imm_tag(obj);
  }
  return get_tag(obj);
}
static inline bool is_heap_object(gc_obj obj) {
  return !is_fixnum(obj) && !is_literal(obj);
}

bcfunc const *closure_code_ptr(closure_s const *clo);
string_s *get_sym_name(symbol *s);
INLINE size_t heap_object_size(void *obj);
typedef void (*trace_callback)(gc_obj *obj, void *ctx);
INLINE void trace_heap_object(gc_header *obj, trace_callback visit, void *ctx);

const char *type_tag_name(uint8_t tag);
void print_type_tag(FILE *file, uint8_t tag);
void print_obj(gc_obj obj, FILE *file);
