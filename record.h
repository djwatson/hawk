#pragma once

#include "bc.h"
#include "emit.h"
#include "ir.h"
#include "types.h"

typedef struct sentry {
  bool changed;
  bool live;
  slot loc;
} sentry;

typedef struct trace_state {
  sentry *stack;
  uint16_t stack_off;
  bc *start_ins;
  uint8_t depth;
  bc **downrec;
  bool skip_start_check;
} trace_state;

typedef struct record_state {
  trace *cur_trace;
  trace_state trace_state;
  trace **traces;
  emit_state emit_state;
} record_state;

struct vm_state;
void record_init(record_state *record);
void record_start(struct vm_state *state, bc *pc, gc_obj *stack);
void record_start_side(struct vm_state *state, bc *pc, gc_obj *stack,
                       snap *snap);
void free_traces(struct vm_state *state);
