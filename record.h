#pragma once

#include "bc.h"
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
} trace_state;

typedef struct record_state {
  trace *cur_trace;
  trace_state trace_state;
  trace **traces;
} record_state;

struct vm_state;
void record_start(struct vm_state *state, bc *pc, gc_obj *stack);
