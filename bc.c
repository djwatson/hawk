#include "bc.h"
#include <stdlib.h>
#include <string.h>

char *bc_names[] = {
#define X(name, type) #name,
    OPS
#undef X
};

static void live_range(bc_live *live, unsigned start, unsigned end, bool set) {
  for (unsigned i = start; i < end && i < 256; i++) {
    uint64_t bit = UINT64_C(1) << (i % 64);
    if (set)
      live->bits[i / 64] |= bit;
    else
      live->bits[i / 64] &= ~bit;
  }
}

bc_live *bc_liveness(const bc *code, size_t count) {
  bc_live *in = calloc(count, sizeof(*in));
  if (!in)
    abort();
  bool changed;
  do {
    changed = false;
    for (size_t pos = count; pos-- > 0;) {
      bc op = code[pos];
      bc_live live = {};
      int64_t next = (int64_t)pos + 1, branch = -1;
      switch (op.op) {
      case OP_RET: case OP_IRET: case OP_RETN: case OP_HALT:
      case OP_LCALLT: case OP_LCALLT_N: case OP_APPLY:
      case OP_CALLCC: case OP_CALLCC_RESUME: case OP_ARGCNT_ERROR:
        next = -1;
        break;
      case OP_JMP:
        next = (int64_t)pos + (int16_t)op.data;
        break;
      case OP_IF: case OP_JLT: case OP_JGT: case OP_JLTE: case OP_JGTE:
      case OP_JEQ: case OP_JEQV: case OP_JNUMEQ:
        next = (int64_t)pos + 2;
        if (pos + 1 < count)
          branch = (int64_t)pos + 1 + (int16_t)code[pos + 1].data;
        break;
      default:
        break;
      }
      if (next >= 0 && (uint64_t)next < count)
        live = in[next];
      if (branch >= 0 && (uint64_t)branch < count)
        for (unsigned i = 0; i < 4; i++)
          live.bits[i] |= in[branch].bits[i];

      switch (op.op) {
      case OP_ADD: case OP_SUB: case OP_MUL: case OP_DIV: case OP_QUOTIENT:
      case OP_MOD: case OP_MEMQ: case OP_MEMV: case OP_ALLOC: case OP_LOAD:
      case OP_LOAD_CHAR: case OP_LOAD_BYTE: case OP_FLVECTOR_REF:
      case OP_CONS: case OP_RECT: case OP_GUARD: case OP_GUARDMASK:
        live_range(&live, op.reg, op.reg + 1, false);
        live_range(&live, op.v1, op.v1 + 1, true);
        live_range(&live, op.v2, op.v2 + 1, true);
        break;
      case OP_EXACT: case OP_TRUNCATE: case OP_INEXACT: case OP_MOV:
      case OP_CHAR_INTEGER: case OP_INTEGER_CHAR:
        live_range(&live, op.reg, op.reg + 1, false);
        live_range(&live, op.data, op.data + 1, true);
        break;
      case OP_CAR: case OP_CDR: case OP_CLOSURE_GET:
        live_range(&live, op.reg, op.reg + 1, false);
        live_range(&live, op.v1, op.v1 + 1, true);
        break;
      case OP_KSHORT: case OP_CONST: case OP_LOOKUP:
        live_range(&live, op.reg, op.reg + 1, false);
        break;
      case OP_STORE: case OP_STORE_CHAR: case OP_STORE_BYTE:
      case OP_FLVECTOR_SET:
        live_range(&live, op.reg, op.reg + 1, true);
        [[fallthrough]];
      case OP_ABC: case OP_JLT: case OP_JGT: case OP_JLTE: case OP_JGTE:
      case OP_JEQ: case OP_JEQV: case OP_JNUMEQ:
        live_range(&live, op.v1, op.v1 + 1, true);
        live_range(&live, op.v2, op.v2 + 1, true);
        break;
      case OP_CLOSURE_SET:
        live_range(&live, op.reg, op.reg + 1, true);
        live_range(&live, op.v1, op.v1 + 1, true);
        break;
      case OP_DEFINE: case OP_RET: case OP_IRET: case OP_HALT:
        live_range(&live, op.reg, op.reg + 1, true);
        break;
      case OP_RETN:
        live_range(&live, op.reg, op.reg + op.data, true);
        break;
      case OP_WRITE:
        live_range(&live, op.v1, op.v1 + 1, true);
        break;
      case OP_IF:
        live_range(&live, op.data, op.data + 1, true);
        break;
      case OP_CLOSURE:
        live_range(&live, op.reg, op.reg + op.data + 1, true);
        break;
      case OP_FOREIGN_CALL:
        live_range(&live, op.reg, op.reg + 1, false);
        live_range(&live, op.v1, op.v1 + op.v2, true);
        break;
      case OP_LCALL: case OP_LCALLT:
        live_range(&live, op.reg, 256, false);
        live_range(&live, op.reg, op.reg + op.data, true);
        break;
      case OP_LCALL_N: case OP_LCALLT_N:
        live_range(&live, op.reg, 256, true);
        break;
      case OP_APPLY:
        live_range(&live, op.reg, op.reg + 1, true);
        live_range(&live, op.v1, op.v1 + 1, true);
        live_range(&live, op.v2, op.v2 + 1, true);
        break;
      case OP_LOOP: case OP_ILOOP:
        live_range(&live, op.reg, op.reg + op.data, true);
        break;
      case OP_JMP: case OP_ARGCNT_ERROR:
        break;
      default:
        // Entry/rest arguments and continuation operations have dynamic ranges.
        memset(&live, 0xff, sizeof(live));
        break;
      }
      if (memcmp(&live, &in[pos], sizeof(live))) {
        in[pos] = live;
        changed = true;
      }
    }
  } while (changed);
  return in;
}
