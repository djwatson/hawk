#pragma once

#include <limits.h>
#include <stdint.h>

typedef struct bc bc;

typedef struct {
  union {
    int64_t value;
    bc *raddress;
    void *ptr;
  };
} gc_obj;

#define TAG_FIXNUM_LITERAL(n)                                                  \
  (/* 1. The compile-time check */                                             \
   (void)sizeof(char[((int64_t)(n) >= (INT64_MIN / 8) &&                       \
                      (int64_t)(n) <= (INT64_MAX / 8))                         \
                         ? 1                                                   \
                         : -1]),                                               \
                                                                               \
   /* 2. The resulting value */                                                \
   (gc_obj){.value = (int64_t)(n) * 8})

typedef struct gc_header {
  union {
    struct {
      uint32_t type;
      uint32_t rc;
    };
    uint64_t fwdtag;
  };
  struct gc_header *fwd;
} gc_header;

typedef struct bcfunc {
  gc_header header;
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
  X(UNUSED2, 0x19)                                                             \
  X(BOX, 0x21)                                                                 \
  X(CONT, 0x29)                                                                \
  X(RECORD, 0x31)

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
gc_header *to_gc_header(gc_obj obj);
symbol *to_symbol(gc_obj obj);
closure_s *to_closure(gc_obj obj);
cont_s *to_cont(gc_obj obj);
// This one is not PTR, but anything!
void *to_raw_ptr(gc_obj obj);
string_s *to_string(gc_obj obj);
flonum_s *to_flonum(gc_obj obj);
int64_t to_fixnum(gc_obj obj);
cons_s *to_cons(gc_obj obj);
vector_s *to_vector(gc_obj obj);
char to_char(gc_obj obj);
bc *to_return_address(gc_obj obj);
bcfunc *to_func(gc_obj obj);

bcfunc const *closure_code_ptr(closure_s const *clo);
string_s *get_sym_name(symbol *s);
gc_obj tag_header(gc_header *s, uint8_t tag);
uint8_t get_tag(gc_obj obj);
uint8_t get_imm_tag(gc_obj obj);
uint32_t get_ptr_tag(gc_obj obj);
bool is_char(gc_obj obj);
bool is_closure(gc_obj obj);
bool is_cons(gc_obj obj);
bool is_ptr(gc_obj obj);
bool is_literal(gc_obj obj);
bool is_string(gc_obj obj);
bool is_record(gc_obj obj);
bool is_symbol(gc_obj obj);
bool is_undefined(gc_obj obj);
bool is_vector(gc_obj obj);
bool is_flonum(gc_obj obj);
bool is_fixnum(gc_obj obj);
bool is_func(gc_obj obj);
bool is_heap_object(gc_obj obj);
gc_obj tag_fixnum(int64_t num);
gc_obj tag_string(string_s *s);
gc_obj tag_flonum(flonum_s *s);
gc_obj tag_cons(cons_s *s);
gc_obj tag_vector(vector_s *s);
gc_obj tag_cont(closure_s *s);
gc_obj tag_closure(closure_s *s);
gc_obj tag_char(char ch);
gc_obj tag_return_address(bc *pc);
gc_obj tag_func(bcfunc *func);
gc_obj tag_ptr(void *ptr);
gc_obj tag_void(void *ptr, uint8_t tag);
