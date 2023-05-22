#include "bytecode.h"
// clang-format off
const char* ins_names[] = {
  "FUNC",
  "KSHORT",
  "ISGE",
  "JMP",
  "RET1",
  "SUBVN",
  "CALL",
  "ADDVV",
  "HALT",
  "ALLOC",
  "ISLT",
  "ISF",
  "SUBVV",
  "GGET",
  "GSET",
  "KFUNC",
  "CALLT",
  "KONST",
  "MOV",
  "ISEQ",
  "ADDVN",
  "JISEQ",
  "JISLT",
  "JFUNC",
  "JLOOP",
  "GUARD",
  "MULVV",
  "BOX",
  "UNBOX",
  "SET-BOX!",
  "CLOSURE",
  "CLOSURE-GET",
  "CLOSURE-PTR",
  "CLOSURE-SET",
  "EQ",
  "CONS",
  "CAR",
  "CDR",
  "MAKE-VECTOR",
  "VECTOR-SET!",
  "VECTOR-REF",
  "VECTOR-LENGTH",
  "SET-CAR!",
  "SET-CDR!",
  "WRITE",
  "STRING-LENGTH",
  "STRING-REF",
  "STRING-SET!",
  "MAKE-STRING",
  "APPLY",
  "SYMBOL->STRING",
  "STRING->SYMBOL",
  "CHAR->INTEGER",
  "INTEGER->CHAR",
  "REM",
  "DIV",
  "CALLCC",
  "CALLCC-RESUME",
  "OPEN",
  "CLOSE",
  "READ",
  "PEEK",
  "WRITE-U8",
  "JEQ",
  "INEXACT",
  "EXACT",
};
// clang-format on
