#include <stdio.h>
#include "types.h"

// Mostly for debugging.  Actual scheme display/write is done from scheme.
void print_obj(long obj) {
  auto type = obj & TAG_MASK;
  switch(type) {
  case FIXNUM_TAG: {
    printf("%lx", obj >> 3);
    break;
  }
  case PTR_TAG: {
    printf("PTR:%lx", obj-1);
    break;
  }
  case FLONUM_TAG: {
    auto f = (flonum_s*)(obj-FLONUM_TAG);
    printf("%f", f->x);
    break;
  }
  case CONS_TAG: {
    printf("CONS");
    break;
  }
  case SYMBOL_TAG: {
    printf("SYMBOL");
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
    } else {
      printf("Unknown immediate: %lx\n", obj);
    }
    break;
  }
  }
}
