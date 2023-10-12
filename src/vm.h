// Copyright 2023 Dave Watson

#pragma once

#include <stdint.h>

#include "types.h"

void run(bcfunc *func, int64_t argcnt, const gc_obj *args);
bcfunc *find_func_for_frame(const uint32_t *pc);
void free_vm();

extern bcfunc **funcs;

#define hotmap_sz 64
#define hotmap_cnt 200
#define hotmap_loop 2
#define hotmap_rec 1
#define hotmap_tail_rec 1
#define hotmap_mask (hotmap_sz - 1)

gc_obj vm_read_char(port_s *port);
gc_obj vm_peek_char(port_s *port);
gc_obj vm_string_symbol(string_s *str);
void vm_write(gc_obj obj, gc_obj port);
void vm_make_string(gc_obj str, gc_obj ch);
void vm_make_vector(gc_obj vec, gc_obj v);
gc_obj vm_callcc(gc_obj *frame);
gc_obj vm_cc_resume(gc_obj c);
void expand_stack(gc_obj **o_frame);
gc_obj vm_length(gc_obj fb);
gc_obj vm_memq(gc_obj fb, gc_obj fc);
gc_obj vm_assq(gc_obj fb, gc_obj fc);
gc_obj vm_assv(gc_obj fb, gc_obj fc);
