#pragma once

#include <string>
#include <unordered_map>
#include <vector>

// clang-format off
enum {
  FUNC=0,
  KSHORT,
  ISGE,
  JMP,
  RET1,
  SUBVN,
  CALL,
  ADDVV,
  HALT,
  ALLOC,
  ISLT, //10
  ISF,
  SUBVV,
  GGET,
  GSET,
  KFUNC,
  CALLT,
  KONST,
  MOV,
  ISEQ,
  ADDVN, //20
  JISEQ,
  JISLT,
  JFUNC,
  JLOOP,
  GUARD,
  MULVV,
  BOX,
  UNBOX,
  SET_BOX,
  CLOSURE,
  CLOSURE_GET,
  CLOSURE_PTR,
  CLOSURE_SET,
  EQ,
  CONS,
  CAR,
  CDR,
  MAKE_VECTOR,
  VECTOR_SET,
  VECTOR_REF,
  VECTOR_LENGTH,
  SET_CAR,
  SET_CDR,
  DISPLAY,
  STRING_LENGTH,
  STRING_REF,
  STRING_SET,
  MAKE_STRING,
  APPLY,
  SYMBOL_STRING,
  STRING_SYMBOL,
  CHAR_INTEGER,
  INTEGER_CHAR,
  REM,
  DIV,
  CALLCC,
  CALLCC_RESUME,
  OPEN,
  CLOSE,
  READ,
  PEEK,
  INS_MAX
};
// clang-format on

extern const char *ins_names[];
extern long *const_table;

#define CODE(i, a, b, c) ((c << 24) | (b << 16) | (a << 8) | i)
#define INS_OP(i) (i & 0xff)
#define INS_A(i) ((i >> 8) & 0xff)
#define INS_B(i) ((i >> 16) & 0xff)
#define INS_C(i) ((i >> 24) & 0xff)
#define INS_BC(i) (i >> 16)

struct bcfunc {
  std::vector<unsigned int> code;
};
