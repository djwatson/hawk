#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "opcodes.h"

extern const char *ins_names[];
extern long *const_table;
extern unsigned long const_table_sz;

#define CODE(i, a, b, c) (((c) << 24) | ((b) << 16) | ((a) << 8) | (i))
#define CODE_D(i, a, d) (((d) << 16) | ((a) << 8) | (i))
#define INS_OP(i) (i & 0xff)
#define INS_A(i) ((i >> 8) & 0xff)
#define INS_B(i) ((i >> 16) & 0xff)
#define INS_C(i) ((i >> 24) & 0xff)
#define INS_D(i) (i >> 16)

struct bcfunc {
  std::vector<unsigned int> code;
  std::string name;
};
