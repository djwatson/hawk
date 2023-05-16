#include "types.h"
#include <stdio.h>

// Mostly for debugging.  Actual scheme display/write is done from scheme.
void print_obj(long obj, FILE* file) {
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
      auto str = (string_s *)(obj - PTR_TAG);
      fprintf(file, "%s", str->str);
    } else if (ptrtype == VECTOR_TAG) {
      auto v = (vector_s *)(obj - PTR_TAG);
      fprintf(file, "#(");
      for (long i = 0; i < v->len; i++) {
        if (i != 0) {
          fprintf(file, " ");
        }
        print_obj(v->v[i], file);
      }
      fprintf(file, ")");
    } else {
      fprintf(file, "PTR:%lx", ptrtype);
    }
    break;
  }
  case FLONUM_TAG: {
    auto f = (flonum_s *)(obj - FLONUM_TAG);
    fprintf(file, "%f", f->x);
    break;
  }
  case CONS_TAG: {
    auto c = (cons_s *)(obj - CONS_TAG);
    fprintf(file, "(");
    while ((c->b & TAG_MASK) == CONS_TAG) {
      print_obj(c->a, file);
      c = (cons_s *)(c->b - CONS_TAG);
      fprintf(file, " ");
    }
    print_obj(c->a, file);
    if (c->b != NIL_TAG) {
      fprintf(file, " . ");
      print_obj(c->b, file);
    }
    fprintf(file, ")");
    break;
  }
  case SYMBOL_TAG: {
    auto sym = (symbol *)(obj - SYMBOL_TAG);
    fprintf(file, "%s", sym->name->str);
    break;
  }
  case CLOSURE_TAG: {
    fprintf(file, "<closure>");
    break;
  }
  case UNUSED_TAG: {
    fprintf(file, "<unused tag>");
    break;
  }
  case LITERAL_TAG: {
    if (obj == TRUE_REP) {
      fprintf(file, "#t");
    } else if (obj == FALSE_REP) {
      fprintf(file, "#f");
    } else if (obj == NIL_TAG) {
      fprintf(file, "()");
    } else if (obj == EOF_TAG) {
      fprintf(file, "<eof>");
    } else if (obj == UNDEFINED_TAG) {
      fprintf(file, "<undefined>");
    } else if ((obj & IMMEDIATE_MASK) == CHAR_TAG) {
      fprintf(file, "%c", (char)(obj >> 8));
    } else {
      fprintf(file, "Unknown immediate: %lx\n", obj);
    }
    break;
  }
  }
}
