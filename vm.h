#pragma once

#include <stdint.h>

#include "bytecode.h"
#include "types.h"

void run(bcfunc *func, long argcnt, const long *args);
bcfunc *find_func_for_frame(const uint32_t *pc);
void free_vm();

extern bcfunc **funcs;

#define hotmap_sz 64
#define hotmap_cnt 200
#define hotmap_loop 3
#define hotmap_rec 1
#define hotmap_tail_rec 1
#define hotmap_mask (hotmap_sz - 1)

__attribute__((always_inline)) long vm_read_char(port_s *port);
__attribute__((always_inline)) long vm_peek_char(port_s *port);
void vm_write(long obj, long port);
