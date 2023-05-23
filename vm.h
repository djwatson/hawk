#pragma once

#include "bytecode.h"

void run(bcfunc *func, long argcnt, long *args);
bcfunc* find_func_for_frame(uint32_t* pc);

extern std::vector<bcfunc *> funcs;

static constexpr int hotmap_sz = 64;
static constexpr int hotmap_cnt = 200;
static constexpr int hotmap_rec = 1;
static constexpr int hotmap_tail_rec = 1;
static constexpr int hotmap_mask = (hotmap_sz - 1);
