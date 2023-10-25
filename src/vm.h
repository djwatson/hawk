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
#define hotmap_loop 3
#define hotmap_rec 1
#define hotmap_tail_rec 1
#define hotmap_mask (hotmap_sz - 1)

ALIGNED8 gc_obj vm_read_char(gc_obj p);
ALIGNED8 gc_obj vm_peek_char(gc_obj p);
ALIGNED8 gc_obj vm_string_symbol(gc_obj in);
ALIGNED8 void vm_write(gc_obj obj, gc_obj port);
ALIGNED8 void vm_make_string(gc_obj str, gc_obj ch);
ALIGNED8 void vm_make_vector(gc_obj vec, gc_obj v);
ALIGNED8 gc_obj vm_callcc(const gc_obj *frame);
ALIGNED8 gc_obj *vm_cc_resume(gc_obj c);
void expand_stack(gc_obj **o_frame);
ALIGNED8 gc_obj vm_length(gc_obj fb);
ALIGNED8 gc_obj vm_memq(gc_obj fb, gc_obj fc);
ALIGNED8 gc_obj vm_assq(gc_obj fb, gc_obj fc);
ALIGNED8 gc_obj vm_assv(gc_obj fb, gc_obj fc);
ALIGNED8 void vm_string_copy(gc_obj tostr, gc_obj tostart, gc_obj fromstr,
                    gc_obj fromstart, gc_obj fromend);

static inline uint32_t hotmap_hash(const uint32_t *pc) {
  return (((uint64_t)pc) >> 2) & hotmap_mask;
}
