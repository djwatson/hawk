#pragma once

#include <vector>
#include <string>
#include <unordered_map>

#define UNDEFINED 27

enum {
  RET=0,
  KSHORT,
  ISGE,
  JMP,
  RET1,
  SUBVN,
  CALL,
  ADDVV,
  HALT,
  ALLOC,
  ISLT,
  ISF,
  SUBVV,
  GGET,
  GSET,
  KFUNC,
  CALLT,
  KONST,
  MOV,
  ISEQ,
  ADDVN,
  JISEQ,
  JISLT,
};

extern const char* ins_names[];

#define CODE(i,a,b,c) ((c << 24) | (b << 16) | (a << 8) | i)
#define INS_OP(i) (i&0xff)
#define INS_A(i) ((i>>8)&0xff)
#define INS_B(i) ((i>>16)&0xff)
#define INS_C(i) ((i>>24)&0xff)
#define INS_BC(i) (i>>16)

struct bcfunc {
  std::vector<unsigned int> code;
  std::vector<unsigned long> consts;
};

struct symbol {
  std::string name;
  unsigned long val;
};

