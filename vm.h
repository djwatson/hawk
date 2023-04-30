#pragma once

#include "bytecode.h"

void run();

extern std::vector<bcfunc *> funcs;

static constexpr int hotmap_sz = 64;
static constexpr int hotmap_cnt = 200;
static constexpr int hotmap_rec = 1;
static constexpr int hotmap_tail_rec = 1;
static constexpr int hotmap_mask = (hotmap_sz - 1);
