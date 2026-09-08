#pragma once

#include "asm.h"
#include "ir.h"

trace_fn emit(trace *t, emit_state *s, uint8_t link_entry_snap);
