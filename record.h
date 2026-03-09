#pragma once

#include "bc.h"
#include "emit.h"
#include "hashtable.h"
#include "ir.h"
#include "types.h"

typedef struct sentry {
  bool changed;
  bool live;
  slot loc;
} sentry;

typedef struct blacklist_entry {
  bc *key;
  uint32_t value;
} blacklist_entry;

typedef struct trace_state {
  sentry *stack;
  uint16_t stack_off;
  bc *start_ins;
  bool start_is_ret;
  uint8_t depth;
  bc **downrec;
  const snap *poly_entry;
  uint32_t start_record_size;
} trace_state;

typedef struct record_state {
  trace *cur_trace;
  trace_state trace_state;
  trace **traces;
  emit_state emit_state;
  blacklist_entry *blacklist;
} record_state;

struct vm_state;
void record_init(record_state *record);
void record_start(struct vm_state *state, bc *pc, bc instr, gc_obj *stack);
void record_start_poly(struct vm_state *state, bc *pc, bc instr, gc_obj *stack,
                       snap *side_snap);
void record_start_side(struct vm_state *state, bc *pc, bc instr, gc_obj *stack,
                       snap *side_snap);
void free_traces(struct vm_state *state);
