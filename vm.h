#pragma once

#include "bytecode.h"

void run();

extern std::vector<bcfunc*> funcs;
extern std::unordered_map<std::string, symbol*> symbol_table;

static constexpr int hotmap_sz = 64;
static constexpr int hotmap_cnt = 200;
static constexpr int hotmap_rec = 1;
static constexpr int hotmap_tail_rec = 1;
static constexpr int hotmap_mask = (hotmap_sz-1);

