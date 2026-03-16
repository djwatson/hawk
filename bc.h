#pragma once

#include <stdint.h>

// Things we WANT in bytecode:
// Things that deal with types or the stack
// Things that are hardware instructions

// FUNCV - conditional arity match function entry.
// IFUNC, IFUNCV
// CALLCC/CALLCC_RESUME
// LOAD_CHAR
// STORE_CHAR
// INTEGER->CHAR, CHAR->INTEGER
// APPLY
// more comparisons - GT,LT,GE,LE,EQ,EQV,EQUAL?
// more math - MUL DIV MOD
// FCALL
// EXACT, INEXACT

// optional:
// even more math - bit ops
// LOOP? JLOOP, ILOOP, LJMP
// RETN

// These would make bytecode smaller/more efficient:
// ADDVN, SUBVN?
// JCMP?
// ALLOC can inline args
// some calls like GCALL / GCALLT (global calls, inline the CLOSURE_GET)
// LOAD/STORE with inline args

// These would make the interpreter faster, but have no effect on JIT:
// More scheme ops: MEMQ,ASSV,ASSQ, VECTOR,CAR,CDR,CONS
// make-vector, make-string, vector-ref, string-ref, vector-length,string-length
// vector-set!, string-set!, string-copy, set-car!, set-cdr!
// open, close, file-exists?, delete-file
// round, sin, sqrt, atan, cos, truncate, floor, ceiling, exp, log, tan , asin,
// acos
#define OPS                                                                    \
  X(ADD, ABC)                                                                  \
  X(SUB, ABC)                                                                  \
  X(MUL, ABC)                                                                  \
  X(DIV, ABC)                                                                  \
  X(QUOTIENT, ABC)                                                             \
  X(MOD, ABC)                                                                  \
  X(EXACT, AD)                                                                 \
  X(TRUNCATE, AD)                                                              \
  X(INEXACT, AD)                                                               \
  X(KSHORT, AD)                                                                \
  X(CONST, AD)                                                                 \
  X(MOV, AD)                                                                   \
  X(RET, A)                                                                    \
  X(LOOKUP, AD)                                                                \
  X(DEFINE, AD)                                                                \
  X(WRITE, AD)                                                                 \
  X(ALLOC, ABC)                                                                \
  X(STORE, ABC)                                                                \
  X(LOAD, ABC)                                                                 \
  X(FUNC, A)                                                                   \
  X(ARGCNT_ERROR, A)                                                           \
  X(JFUNC, AD)                                                                 \
  X(JLT, ABC)                                                                  \
  X(JGT, ABC)                                                                  \
  X(JLTE, ABC)                                                                 \
  X(JGTE, ABC)                                                                 \
  X(JEQ, ABC)                                                                  \
  X(JEQV, ABC)                                                                 \
  X(GUARD, ABC)                                                                \
  X(IF, AD)                                                                    \
  X(JMP, AD)                                                                   \
  X(CLOSURE_GET, ABC)                                                          \
  X(CLOSURE_SET, ABC)                                                          \
  X(CLOSURE, AD)                                                               \
  X(LCALL, AD)                                                                 \
  X(LCALLT, AD)                                                                \
  X(HALT, A)                                                                   \
  X(IFUNC, A)
typedef enum : uint8_t {
#define X(name, type) OP_##name,
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
extern char *bc_names[];
