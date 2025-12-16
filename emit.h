#pragma once

#include "asm.h"
#include "ir.h"

struct record_state;

trace_fn emit(trace *t, emit_state *s, struct record_state *record,
              const snap *poly_entry);
