#pragma once

#include <stdint.h>

#include "defs.h"
#include "types.h"

void run(bcfunc *func, long argcnt, const long *args);
bcfunc *find_func_for_frame(const uint32_t *pc);
void free_vm();

extern bcfunc **funcs;

#define hotmap_sz 64
#define hotmap_cnt 200
#define hotmap_loop 2
#define hotmap_rec 1
#define hotmap_tail_rec 1
#define hotmap_mask (hotmap_sz - 1)

long vm_read_char(port_s *port);
long vm_peek_char(port_s *port);
long vm_string_symbol(string_s *str);
void vm_write(long obj, long port);
void vm_make_string(long str, long ch);
void vm_make_vector(long vec, long v);
long vm_callcc(long *frame);
long vm_cc_resume(long c);
void expand_stack(long **o_frame);
long vm_length(long fb);
long vm_memq(long fb, long fc);
long vm_assq(long fb, long fc);
long vm_assv(long fb, long fc);
