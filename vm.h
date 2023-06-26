#pragma once

#include "bytecode.h"
#include "vector.h"

void run(bcfunc *func, long argcnt, long *args);
bcfunc *find_func_for_frame(uint32_t *pc);
void free_vm();

vec_proto(bcfunc*, bcfunc);
extern vec funcs;

static constexpr int hotmap_sz = 64;
static constexpr int hotmap_cnt = 200;
static constexpr int hotmap_rec = 1;
static constexpr int hotmap_tail_rec = 1;
static constexpr int hotmap_mask = (hotmap_sz - 1);
