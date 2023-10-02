#pragma once

#include <stdint.h>
#include <stdio.h>

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
#define FORWARD_TAG 0x7

#define TAG_MASK 0x7

// Object tags, use PTR_TAG on ptr, and OBJ_TAG in object itself as first field.
// Bottom three bits are '001' so it is also recognized as a PTR using the same
// tag.
#define STRING_TAG 0x9
#define VECTOR_TAG 0x11
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
  unsigned long len;
  char str[];
} string_s;

struct tv {
  uint16_t key;
};
typedef struct symbol {
  uint32_t type;
  uint32_t rc;
  long name; // string_s PTR_TAG'd value
  long val;
  long opt;
  struct tv *lst;
} symbol;

typedef struct vector_s {
  uint32_t type;
  uint32_t rc;
  unsigned long len;
  long v[];
} vector_s;

typedef struct cons_s {
  uint32_t type;
  uint32_t rc;
  long a;
  long b;
} cons_s;

typedef struct closure_s {
  uint32_t type;
  uint32_t rc;
  unsigned long len;
  long v[];
} closure_s;

typedef struct port_s {
  uint32_t type;
  uint32_t rc;
  long input_port;
  long fd;
  FILE *file;
  long eof;
  long buf_pos;
  long buf_sz;
  char *in_buffer;
} port_s;

void print_obj(long obj, FILE *file);
long from_c_str(const char *s);
long equalp(long a, long b);

// GC interface:
__attribute((always_inline)) size_t heap_object_size(long *obj);
typedef void (*trace_callback)(long *field, void *ctx);
__attribute((always_inline)) void
trace_heap_object(long *obj, trace_callback visit, void *ctx);
