#pragma once

#include "bytecode.h"

void run();

extern std::vector<bcfunc*> funcs;
extern std::unordered_map<std::string, symbol*> symbol_table;

constexpr int hotmap_sz = 64;
constexpr int hotmap_cnt = 100;
constexpr int hotmap_rec = 1;
constexpr int hotmap_tail_rec = 2;

