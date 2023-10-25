// Copyright 2023 Dave Watson

#include "types.h"
#include <inttypes.h>
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

// TODO(djwatson): Note that unlike SCM, this may cause a stack
//       overflow when we recurse for car and vectors. maybe use an
//       explicit stack here.
static const int64_t kb = -20;
static const int64_t k0 = 200;
typedef struct {
  bool v;
  int64_t k;
} ep_result;
static ep_result ep(uf *ht, bool unused, gc_obj a, gc_obj b, int64_t k);
static ep_result equalp_interleave(uf *ht, bool fast, gc_obj a, gc_obj b,
                                   int64_t k) {
  // eq?
  if (a.value == b.value) {
    return (ep_result){true, k};
  }

  // Check cons, vector, string for equalp?
  // cons and vector check unionfind table for cycles.
  if (is_cons(a)) {
    if (is_cons(b)) {
      auto cell_a = to_cons(a);
      auto cell_b = to_cons(b);
      if (!fast && unionfind(ht, a.value, b.value)) {
        return (ep_result){true, 0};
      }
      // Decrement k once
      auto res = ep(ht, fast, cell_a->a, cell_b->a, k - 1);
      if (true != res.v) {
        return res;
      }
      // And pass k through.
      MUSTTAIL return ep(ht, fast, cell_a->b, cell_b->b, res.k);
    }
    return (ep_result){false, k};
  }
  if (is_ptr(a)) {
    if (!is_ptr(b)) {
      return (ep_result){false, k};
    }
    auto ta = get_ptr_tag(a);
    auto tb = get_ptr_tag(b);
    if (ta != tb) {
      return (ep_result){false, k};
    }
    if (ta == STRING_TAG) {
      auto sa = to_string(a);
      auto sb = to_string(b);
      if (sa->len.value != sb->len.value) {
        return (ep_result){false, k};
      }
      if (strcmp(sa->str, sb->str) == 0) {
        return (ep_result){true, k};
      }
      return (ep_result){false, k};
    }
  }
  if (is_vector(a) && is_vector(b)) {
    auto va = to_vector(a);
    auto vb = to_vector(b);
    if (va->len.value != vb->len.value) {
      return (ep_result){false, k};
    }
    if (!fast && unionfind(ht, a.value, b.value)) {
      return (ep_result){true, 0};
    }
    // Decrement K once for the vector, but return same K value
    uint64_t lim = to_fixnum(va->len);
    for (uint64_t i = 0; i < lim; i++) {
      auto res = ep(ht, fast, va->v[i], vb->v[i], k - 1);
      if (true != res.v) {
        return res;
      }
    }
    return (ep_result){true, k};
  }
  // eqp?
  if (is_flonum(a)) {
    if (!is_flonum(b)) {
      return (ep_result){false, k};
    }
    auto sa = to_flonum(a);
    auto sb = to_flonum(b);
    if (sa->x == sb->x) {
      return (ep_result){true, k};
    }
    return (ep_result){false, k};
  }
  return (ep_result){false, k};
}

static ep_result ep(uf *ht, bool unused, gc_obj a, gc_obj b, int64_t k) {
  if (k <= 0) {
    if (k == kb) {
      MUSTTAIL return equalp_interleave(ht, true, a, b, k0 * 2);
    } else {
      MUSTTAIL return equalp_interleave(ht, false, a, b, k);
    }
  } else {
    MUSTTAIL return equalp_interleave(ht, true, a, b, k);
  }
}

ALIGNED8 gc_obj equalp(gc_obj a, gc_obj b) {
  uf ht;
  uf_init(&ht);
  int64_t k = k0;

  ep_result res = ep(&ht, true, a, b, k);

  uf_free(&ht);
  if (res.v) {
    return TRUE_REP;
  }
  return FALSE_REP;
}

void print_obj(gc_obj obj, FILE *file) {
  auto type = get_tag(obj);
  switch (type) {
  case FIXNUM_TAG: {
    fprintf(file, "%" PRId64, to_fixnum(obj));
    break;
  }
  case PTR_TAG: {
    auto ptrtype = get_ptr_tag(obj);
    if (ptrtype == STRING_TAG) {
      auto str = to_string(obj);
      fputs(str->str, file);
    } else if (ptrtype == PORT_TAG) {
      fputs("#<port>", file);
    } else {
      fprintf(file, "PTR:%x", ptrtype);
    }
    break;
  }
  case VECTOR_TAG: {
    auto v = to_vector(obj);
    fputs("#(", file);
    for (uint64_t i = 0; i < to_fixnum(v->len); i++) {
      if (i != 0) {
        fputc(' ', file);
      }
      print_obj(v->v[i], file);
    }
    fputc(')', file);
    break;
  }
  case FLONUM_TAG: {
    auto f = to_flonum(obj);
    char buffer[40];
    snprintf(buffer, 40 - 3, "%g", f->x);
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
    auto c = to_cons(obj);
    fputc('(', file);
    while (is_cons(c->b)) {
      print_obj(c->a, file);
      c = to_cons(c->b);
      fputc(' ', file);
    }
    print_obj(c->a, file);
    if (c->b.value != NIL_TAG) {
      fputs(" . ", file);
      print_obj(c->b, file);
    }
    fputc(')', file);
    break;
  }
  case SYMBOL_TAG: {
    auto sym = to_symbol(obj);
    string_s *sym_name = get_sym_name(sym);
    fputs(sym_name->str, file);
    break;
  }
  case CLOSURE_TAG: {
    closure_s *clo = to_closure(obj);
    bcfunc *func = closure_code_ptr(clo);
    fprintf(file, "#<procedure %s>", func->name);
    break;
  }
  case LITERAL_TAG: {
    if (obj.value == TRUE_REP.value) {
      fputs("#t", file);
    } else if (obj.value == FALSE_REP.value) {
      fputs("#f", file);
    } else if (obj.value == NIL_TAG) {
      fputs("()", file);
    } else if (obj.value == EOF_TAG) {
      fputs("<eof>", file);
    } else if (is_undefined(obj)) {
      fputs("<undefined>", file);
    } else if (is_char(obj)) {
      fputc(to_char(obj), file);
    } else {
      fprintf(file, "Unknown immediate: %" PRIx64 "\n", obj.value);
    }
    break;
  }
  default:
    break;
  }
}

EXPORT gc_obj from_c_str(const char *s) {
  auto len = (int64_t)strlen(s);
  string_s *str = GC_malloc(sizeof(string_s) + len + 1);
  *str = (string_s){STRING_TAG, 0, tag_fixnum(len)};
  memcpy(str->str, s, len);
  str->str[len] = '\0';
  return tag_string(str);
}

// GC interface:

INLINE inline size_t heap_object_size(void *obj) {
  auto type = *(uint32_t *)obj;
  switch (type) {
  case FLONUM_TAG:
    return sizeof(flonum_s);
  case STRING_TAG: {
    auto str = (string_s *)obj;
    return to_fixnum(str->len) * sizeof(char) + sizeof(string_s) +
           1 /* null tag */;
  }
  case SYMBOL_TAG:
    return sizeof(symbol);
  case CONT_TAG:
  case VECTOR_TAG: {
    auto vec = (vector_s *)obj;
    return to_fixnum(vec->len) * sizeof(gc_obj) + 16;
  }
  case CONS_TAG:
    return sizeof(cons_s);
  case CLOSURE_TAG: {
    auto clo = (closure_s *)obj;
    return to_fixnum(clo->len) * sizeof(gc_obj) + 16;
  }
  case PORT_TAG:
    return sizeof(port_s);
  default:
    printf("Unknown heap object: %i\n", type);
    abort();
    break;
  }
}

INLINE inline void trace_heap_object(void *obj, trace_callback visit,
                                     void *ctx) {
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
    for (uint64_t i = to_fixnum(vec->len); i > 0; i--) {
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
    for (uint64_t i = to_fixnum(clo->len); i > 1; i--) {
      visit(&clo->v[i] - 1, ctx);
    }
    break;
  }
  case PORT_TAG:
    break;
  default:
    printf("Unknown heap object: %i\n", type);
    abort();
    break;
  }
}
