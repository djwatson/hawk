#include "types.h"
#include <stdio.h>
#include <string.h>

#include "gc.h"
#include "symbol_table.h"
#include "defs.h"

#define auto __auto_type
#define nullptr NULL

// Mostly for debugging.  Actual scheme display/write is done from scheme.
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
    long ptrtype = *(long *)(obj - PTR_TAG);
    if (ptrtype == STRING_TAG) {
      auto *str = (string_s *)(obj - PTR_TAG);
      fputs(str->str, file);
    } else if (ptrtype == PORT_TAG) {
      fputs("#<port>", file);
    } else if (ptrtype == VECTOR_TAG) {
      auto *v = (vector_s *)(obj - PTR_TAG);
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
    auto *f = (flonum_s *)(obj - FLONUM_TAG);
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
    auto *c = (cons_s *)(obj - CONS_TAG);
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
    auto *sym = (symbol *)(obj - SYMBOL_TAG);
    string_s* sym_name = (string_s*)(sym->name - PTR_TAG);
    fputs(sym_name->str, file);
    break;
  }
  case CLOSURE_TAG: {
    fputs("<closure>", file);
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
  auto *str = (string_s *)GC_malloc(16 + len + 1);
  str->type = STRING_TAG;
  str->len = len << 3;
  memcpy(str->str, s, len);
  str->str[len] = '\0';
  return (long)str | PTR_TAG;
}

long get_symbol_val(const char *name) {
  auto str = from_c_str(name);
  auto *strp = (string_s *)(str - PTR_TAG);
  auto *res = symbol_table_find(strp);
  if (res == nullptr) {
    return UNDEFINED_TAG;
  }
  return res->val;
}
