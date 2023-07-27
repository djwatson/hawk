#pragma once

#include "bytecode.h"
#include <stdint.h>

void run(bcfunc *func, long argcnt, const long *args);
bcfunc *find_func_for_frame(const uint32_t *pc);
void free_vm();

extern bcfunc **funcs;

#define hotmap_sz 64
#define hotmap_cnt 200
#define hotmap_rec 1
#define hotmap_tail_rec 1
#define hotmap_mask (hotmap_sz - 1)
