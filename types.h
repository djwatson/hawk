#pragma once

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
#define FORWARD_TAG 0x4
#define CLOSURE_TAG 0x5
#define SYMBOL_TAG 0x6
#define LITERAL_TAG 0x7

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
#define BOOL_TAG 0x07
#define TRUE_REP 0x0107
#define FALSE_REP 0x0007
#define CHAR_TAG 0x0f
#define NIL_TAG 0x17
#define EOF_TAG 0x1f
#define UNDEFINED_TAG 0x27

#define IMMEDIATE_MASK 0xff

typedef struct flonum_s {
  long type; // TODO: perhaps could save this space by making a NAN-tagged
             // forwarding pointer? otherwise unused.
  double x;
} flonum_s;

typedef struct string_s {
  long type;
  long len;
  char str[];
} string_s;

typedef struct symbol {
  long type; // unused except by GC
  string_s *name;
  long val;
} symbol;

typedef struct vector_s {
  long type;
  long len;
  long v[];
} vector_s;

typedef struct cons_s {
  long type; // unused except by GC
  long a;
  long b;
} cons_s;

typedef struct closure_s {
  long type; // unused except by GC
  long len;
  long v[];
} closure_s;

typedef struct port_s {
  long type; // TODO could merge input_port and type somehow.
  long input_port;
  long fd;
  FILE *file;
  long peek;
} port_s;

void print_obj(long obj, FILE *file);
long from_c_str(const char *s);
long get_symbol_val(const char *name);
