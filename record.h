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

typedef enum trace_type : uint8_t {
  TRACE_TYPE_ROOT,
  TRACE_TYPE_SIDE,
  TRACE_TYPE_POLY_ROOT,
} trace_type;

typedef struct trace_state {
  sentry *stack;
  uint16_t stack_off;
  bc *start_ins;
  uint8_t depth;
  bc **downrec;
  bool skip_start_check;
  trace_type type;
  const snap *poly_entry;
} trace_state;

typedef struct record_state {
  trace *cur_trace;
  trace_state trace_state;
  trace **traces;
  emit_state emit_state;
  bc *patchpc;
  bc old_patch;
} record_state;

struct vm_state;
void record_init(record_state *record);
void record_start(struct vm_state *state, bc *pc, gc_obj *stack,
                  const snap *poly_entry);
void record_start_side(struct vm_state *state, bc *pc, gc_obj *stack,
                       snap *snap);
void free_traces(struct vm_state *state);
