#pragma once

#include <stdint.h>

// Things we WANT in bytecode:
// Things that deal with types or the stack
// Things that are hardware instructions

// WRITE -debug?
// LCALLT
// FUNCV - actually all CFUNC
// IFUNC, IFUNCV
// CFUNC, CFUNCV
// LOOP? JLOOP, ILOOP
// CALLCC/CALLCC_RESUME
// GUARD
// LOAD / LOAD_CHAR
// STORE / STORE_CHAR
// INTEGER->CHAR, CHAR->INTEGER
// APPLY
// ALLOC
// more comparisons - GT,LT,GE,LE,EQ,EQV,EQUAL?
// more math - MUL DIV MOD
// even more math - bit ops
// EXACT, INEXACT
// CLOSURE
// JMP, LJMP??
// FCALL
// RETN

// These would make bytecode smaller/more efficient:
// ADDVN, SUBVN?
// JCMP?

// These would make the interpreter faster, but have no effect on JIT:
// More scheme ops: MEMQ,ASSV,ASSQ, VECTOR,CAR,CDR,CONS
// make-vector, make-string, vector-ref, string-ref, vector-length,string-length
// vector-set!, string-set!, string-copy, set-car!, set-cdr!
// open, close, file-exists?, delete-file
// round, sin, sqrt, atan, cos, truncate, floor, ceiling, exp, log, tan , asin,
// acos
#define OPS                                                                    \
  X(ADD)                                                                       \
  X(SUB)                                                                       \
  X(KSHORT)                                                                    \
  X(CONST)                                                                     \
  X(RET)                                                                       \
  X(LOOKUP)                                                                    \
  X(FUNC)                                                                      \
  X(JFUNC)                                                                     \
  X(LT)                                                                        \
  X(IF)                                                                        \
  X(CLOSURE_GET)                                                               \
  X(LCALL)                                                                     \
  X(LCALLT)                                                                    \
  X(HALT)
typedef enum : uint8_t {
#define X(name) OP_##name,
  OPS
#undef X
      OP_INS_MAX,
} ops;

typedef struct bc {
  union {
    struct {
      ops op;
      uint8_t reg;
      union {
        struct {
          uint8_t v1;
          uint8_t v2;
        };
        uint16_t data;
      };
    };
    uint32_t full_data;
  };
} bc;

static_assert(sizeof(bc) == 4, "bc instructions must be 4 bytes");
