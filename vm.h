#pragma once

#include <stdint.h>
#include "bytecode.h"

void run(bcfunc *func, long argcnt, long *args);
bcfunc *find_func_for_frame(uint32_t *pc);
void free_vm();

extern bcfunc** funcs;

#define hotmap_sz 64
#define hotmap_cnt 200
#define hotmap_rec 1
#define hotmap_tail_rec 1
#define hotmap_mask (hotmap_sz - 1)

