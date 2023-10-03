#include "types.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bytecode.h"
#include "defs.h"
#include "gc.h"
#include "symbol_table.h"

#include "unionfind.h"

#define auto __auto_type
#define nullptr NULL

// Straight from the paper https://legacy.cs.indiana.edu/~dyb/pubs/equal.pdf
// Efficient Nondestructive Equality Checking for Trees and Graphs
// TODO: Note that unlike SCM, this may cause a stack overflow when
//       we recurse for car and vectors. maybe use an explicit stack here.
static const long kb = -20;
static const long k0 = 200;
typedef struct {
  bool v;
  long k;
} ep_result;
static ep_result ep(uf *ht, bool unused, long a, long b, long k);
static ep_result equalp_interleave(uf *ht, bool fast, long a, long b, long k) {
  // eq?
  if (a == b) {
    return (ep_result){true, k};
  }
  // Check cons, vector, string for equalp?
  // cons and vector check unionfind table for cycles.
  if ((a & TAG_MASK) == CONS_TAG) {
    if ((b & TAG_MASK) == CONS_TAG) {
      cons_s *cell_a = (cons_s *)(a - CONS_TAG);
      cons_s *cell_b = (cons_s *)(b - CONS_TAG);
      if (!fast && unionfind(ht, a, b)) {
        return (ep_result){true, 0};
      }
      // Decrement k once
      auto res = ep(ht, fast, cell_a->a, cell_b->a, k - 1);
      if (true != res.v) {
        return res;
      }
      // And pass k through.
      k = res.k;
      MUSTTAIL return ep(ht, fast, cell_a->b, cell_b->b, k);
    }
    return (ep_result){false, k};
  }
  if ((a & TAG_MASK) == PTR_TAG) {
    if ((b & TAG_MASK) != PTR_TAG) {
      return (ep_result){false, k};
    }
    long ta = *(uint32_t *)(a - PTR_TAG);
    long tb = *(uint32_t *)(b - PTR_TAG);
    if (ta != tb) {
      return (ep_result){false, k};
    }
    if (ta == VECTOR_TAG) {
      vector_s *va = (vector_s *)(a - PTR_TAG);
      vector_s *vb = (vector_s *)(b - PTR_TAG);
      if (va->len != vb->len) {
        return (ep_result){false, k};
      }
      if (!fast && unionfind(ht, a, b)) {
        return (ep_result){true, 0};
      }
      // Decrement K once for the vector, but return same K value
      uint64_t lim = va->len >> 3;
      for (uint64_t i = 0; i < lim; i++) {
        auto res = ep(ht, fast, va->v[i], vb->v[i], k - 1);
        if (true != res.v) {
          return res;
        }
      }
      return (ep_result){true, k};
    }
    if (ta == STRING_TAG) {
      string_s *sa = (string_s *)(a - PTR_TAG);
      string_s *sb = (string_s *)(b - PTR_TAG);
      if (sa->len != sb->len) {
        return (ep_result){false, k};
      }
      if (strcmp(sa->str, sb->str) == 0) {
        return (ep_result){true, k};
      }
      return (ep_result){false, k};
    }
  }
  // eqp?
  if ((a & TAG_MASK) == FLONUM_TAG) {
    if ((b & TAG_MASK) != FLONUM_TAG) {
      ep_result res = {false, k};
      return res;
    }
    flonum_s *sa = (flonum_s *)(a - FLONUM_TAG);
    flonum_s *sb = (flonum_s *)(b - FLONUM_TAG);
    if (sa->x == sb->x) {
      ep_result res = {true, k};
      return res;
    } else {
      ep_result res = {false, k};
      return res;
    }
  }
  return (ep_result){false, k};
}

static ep_result ep(uf *ht, bool unused, long a, long b, long k) {
  if (k <= 0) {
    if (k == kb) {
      k = k0 * 2;
      MUSTTAIL return equalp_interleave(ht, true, a, b, k);
    } else {
      MUSTTAIL return equalp_interleave(ht, false, a, b, k);
    }
  } else {
    MUSTTAIL return equalp_interleave(ht, true, a, b, k);
  }
}

long equalp(long a, long b) {
  uf ht;
  uf_init(&ht);
  long k = k0;

  ep_result res = ep(&ht, true, a, b, k);

  uf_free(&ht);
  if (res.v) {
    return TRUE_REP;
  }
  return FALSE_REP;
}

void print_obj(long obj, FILE *file) {
  if (file == nullptr) {
    file = stdout;
  }
  auto type = obj & TAG_MASK;
  switch (type) {
  case FIXNUM_TAG: {
    fprintf(file, "%li", obj >> 3);
    break;
  }
  case PTR_TAG: {
    long ptrtype = *(uint32_t *)(obj - PTR_TAG);
    if (ptrtype == STRING_TAG) {
      auto str = (string_s *)(obj - PTR_TAG);
      fputs(str->str, file);
    } else if (ptrtype == PORT_TAG) {
      fputs("#<port>", file);
    } else if (ptrtype == VECTOR_TAG) {
      auto v = (vector_s *)(obj - PTR_TAG);
      fputs("#(", file);
      for (long i = 0; i < (v->len >> 3); i++) {
        if (i != 0) {
          fputc(' ', file);
        }
        print_obj(v->v[i], file);
      }
      fputc(')', file);
    } else {
      fprintf(file, "PTR:%lx", ptrtype);
    }
    break;
  }
  case FLONUM_TAG: {
    auto f = (flonum_s *)(obj - FLONUM_TAG);
    char buffer[40];
    sprintf(buffer, "%g", f->x);
    if (strpbrk(buffer, ".eE") == nullptr) {
      size_t len = strlen(buffer);
      buffer[len] = '.';
      buffer[len + 1] = '0';
      buffer[len + 2] = '\0';
    }
    fputs(buffer, file);
    break;
  }
  case CONS_TAG: {
    auto c = (cons_s *)(obj - CONS_TAG);
    fputc('(', file);
    while ((c->b & TAG_MASK) == CONS_TAG) {
      print_obj(c->a, file);
      c = (cons_s *)(c->b - CONS_TAG);
      fputc(' ', file);
    }
    print_obj(c->a, file);
    if (c->b != NIL_TAG) {
      fputs(" . ", file);
      print_obj(c->b, file);
    }
    fputc(')', file);
    break;
  }
  case SYMBOL_TAG: {
    auto sym = (symbol *)(obj - SYMBOL_TAG);
    string_s *sym_name = (string_s *)(sym->name - PTR_TAG);
    fputs(sym_name->str, file);
    break;
  }
  case CLOSURE_TAG: {
    closure_s *clo = (closure_s *)(obj - CLOSURE_TAG);
    bcfunc *func = (bcfunc *)clo->v[0];
    fprintf(file, "#<procedure %s>", func->name);
    break;
  }
  case FORWARD_TAG: {
    fputs("<forward tag>", file);
    break;
  }
  case LITERAL_TAG: {
    if (obj == TRUE_REP) {
      fputs("#t", file);
    } else if (obj == FALSE_REP) {
      fputs("#f", file);
    } else if (obj == NIL_TAG) {
      fputs("()", file);
    } else if (obj == EOF_TAG) {
      fputs("<eof>", file);
    } else if (obj == UNDEFINED_TAG) {
      fputs("<undefined>", file);
    } else if ((obj & IMMEDIATE_MASK) == CHAR_TAG) {
      fputc((char)(obj >> 8), file);
    } else {
      fprintf(file, "Unknown immediate: %lx\n", obj);
    }
    break;
  }
  }
}

EXPORT long from_c_str(const char *s) {
  unsigned long len = strlen(s);
  auto str = (string_s *)GC_malloc(16 + len + 1);
  str->type = STRING_TAG;
  str->len = len << 3;
  str->rc = 0;
  memcpy(str->str, s, len);
  str->str[len] = '\0';
  return (long)str | PTR_TAG;
}

// GC interface:

INLINE size_t heap_object_size(long *obj) {
  auto type = *(uint32_t *)obj;
  switch (type) {
  case FLONUM_TAG:
    return sizeof(flonum_s);
  case STRING_TAG: {
    auto str = (vector_s *)obj;
    return (str->len >> 3) * sizeof(char) + 16 + 1 /* null tag */;
  }
  case SYMBOL_TAG:
    return sizeof(symbol);
  case CONT_TAG:
  case VECTOR_TAG: {
    auto vec = (vector_s *)obj;
    return (vec->len >> 3) * sizeof(long) + 16;
  }
  case CONS_TAG:
    return sizeof(cons_s);
  case CLOSURE_TAG: {
    auto clo = (closure_s *)obj;
    return (clo->len >> 3) * sizeof(long) + 16;
  }
  case PORT_TAG:
    return sizeof(port_s);
  default:
    printf("Unknown heap object: %i\n", type);
    abort();
  }
}

INLINE void trace_heap_object(long *obj, trace_callback visit, void *ctx) {
  // printf("Trace heap obj %p\n", obj);
  auto type = *(uint32_t *)obj;
  switch (type) {
  case FLONUM_TAG:
  case STRING_TAG:
    break;
  case SYMBOL_TAG: {
    auto sym = (symbol *)obj;
    // temporarily add back the tag
    visit(&sym->name, ctx);
    visit(&sym->val, ctx);
    break;
  }
  case CONT_TAG:
  case VECTOR_TAG: {
    auto vec = (vector_s *)obj;
    for (long i = (vec->len >> 3); i > 0; i--) {
      visit(&vec->v[i] - 1, ctx);
    }
    break;
  }
  case CONS_TAG: {
    auto cons = (cons_s *)obj;
    visit(&cons->b, ctx);
    visit(&cons->a, ctx);
    break;
  }
  case CLOSURE_TAG: {
    auto clo = (closure_s *)obj;
    // Note start from 1: first field is bcfunc* pointer.
    for (long i = clo->len >> 3; i > 1; i--) {
      visit(&clo->v[i] - 1, ctx);
    }
    break;
  }
  case PORT_TAG:
    break;
  default:
    printf("Unknown heap object: %i\n", type);
    abort();
  }
}
