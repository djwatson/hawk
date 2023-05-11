#include "types.h"
#include <stdio.h>

// Mostly for debugging.  Actual scheme display/write is done from scheme.
void print_obj(long obj) {
  auto type = obj & TAG_MASK;
  switch (type) {
  case FIXNUM_TAG: {
    printf("%li", obj >> 3);
    break;
  }
  case PTR_TAG: {
    long ptrtype = *(long *)(obj - PTR_TAG);
    if (ptrtype == STRING_TAG) {
      auto str = (string_s *)(obj - PTR_TAG);
      printf("%s\n", str->str);
    } else if (ptrtype == VECTOR_TAG) {
      auto v = (vector_s *)(obj - PTR_TAG);
      printf("#(");
      for (long i = 0; i < v->len; i++) {
        if (i != 0) {
          printf(" ");
        }
        print_obj(v->v[i]);
      }
      printf(")");
    } else {
      printf("PTR:%lx", ptrtype);
    }
    break;
  }
  case FLONUM_TAG: {
    auto f = (flonum_s *)(obj - FLONUM_TAG);
    printf("%f", f->x);
    break;
  }
  case CONS_TAG: {
    auto c = (cons_s *)(obj - CONS_TAG);
    printf("(");
    while ((c->b & TAG_MASK) == CONS_TAG) {
      print_obj(c->a);
      c = (cons_s *)(c->b - CONS_TAG);
      printf(" ");
    }
    print_obj(c->a);
    if (c->b != NIL_TAG) {
      printf(" . ");
      print_obj(c->b);
    }
    printf(")");
    break;
  }
  case SYMBOL_TAG: {
    auto sym = (symbol *)(obj - SYMBOL_TAG);
    printf("%s", sym->name->str);
    break;
  }
  case CLOSURE_TAG: {
    printf("<closure>");
    break;
  }
  case UNUSED_TAG: {
    printf("<unused tag>");
    break;
  }
  case LITERAL_TAG: {
    if (obj == TRUE_REP) {
      printf("#t");
    } else if (obj == FALSE_REP) {
      printf("#f");
    } else if (obj == NIL_TAG) {
      printf("()");
    } else if (obj == EOF_TAG) {
      printf("<eof>");
    } else if (obj == UNDEFINED_TAG) {
      printf("<undefined>");
    } else if ((obj & IMMEDIATE_MASK) == CHAR_TAG) {
      printf("%c", (char)(obj >> 8));
    } else {
      printf("Unknown immediate: %lx\n", obj);
    }
    break;
  }
  }
}
