#pragma once

#include "ir.h"
struct trace_result {
  gc_obj *stack;
  snap *snap;
};
typedef struct trace_result (*trace_fn)(gc_obj *stack);

trace_fn emit(trace *t);
