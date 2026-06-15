#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "bc.h"
#include "bigint.h"
#include "ftoa.h"
#include "types.h"

#define X(name, num) #name,
char *low_tag_names[] = {LOW_TAGS};

char *immediate_tag_names[] = {IMMEDIATE_TAGS};

char *ptr_tag_names[] = {PTR_TAGS};
#undef X

bcfunc const *closure_code_ptr(closure_s const *clo) {
  return (bcfunc *)clo->v[0].value;
}

static const char *type_tag_names[256] = {
    [FIXNUM_TAG] = "fix",  [CONS_TAG] = "cons",   [FLONUM_TAG] = "flo",
    [SYMBOL_TAG] = "sym",  [BOOL_TAG] = "bool",   [NIL_TAG] = "nil",
    [EOF_TAG] = "eof",     [STRING_TAG] = "str",  [FUNC_TAG] = "func",
    [VECTOR_TAG] = "vec",  [CONT_TAG] = "cont",   [PTR_TAG] = "ptr",
    [CHAR_TAG] = "char",   [CLOSURE_TAG] = "clo", [UNDEFINED_TAG] = "",
    [RECORD_TAG] = "rec",  [BIGNUM_TAG] = "big",  [RATNUM_TAG] = "rat",
    [COMPNUM_TAG] = "cmp", [PORT_TAG] = "port",   [FLVECTOR_TAG] = "flvec",
};

const char *type_tag_name(uint8_t tag) {
  if ((tag & PORT_IDENTITY) == PORT_IDENTITY) {
    return "port";
  }
  auto name = type_tag_names[tag];
  return name ? name : "?";
}

void print_type_tag(FILE *file, uint8_t tag) {
  auto name = type_tag_name(tag);
  if (name[0] == '\0') {
    fputs("      ", file);
    return;
  }
  fputs(tag == FIXNUM_TAG ? "\e[1;35m" : "\e[1;34m", file);
  fprintf(file, "%-5s", name);
  fputs("\e[m ", file);
}

string_s *get_sym_name(symbol *s) {
  return (string_s *)(s->name.value - PTR_TAG);
}

// This is mostly a debug aid: The scheme-level printer is defined in
// scheme base code itself.
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
    } else if (ptrtype == RATNUM_TAG) {
      auto rat = to_ratnum(obj);
      print_obj(rat->num, file);
      fputc('/', file);
      print_obj(rat->denom, file);
    } else if (ptrtype == COMPNUM_TAG) {
      auto cmp = to_compnum(obj);
      print_obj(cmp->real, file);
      fputc('+', file);
      print_obj(cmp->imag, file);
      fputc('i', file);
    } else if (ptrtype == FLVECTOR_TAG) {
      auto v = to_flvector(obj);
      fputs("#(", file);
      for (uint64_t i = 0; i < to_fixnum(v->len); i++) {
        if (i != 0) {
          fputc(' ', file);
        }
        char *buffer = ftoa_fast(v->v[i]);
        fputs(buffer, file);
        free(buffer);
      }
      fputc(')', file);
    } else if (ptrtype == RECORD_TAG) {
      fputs("#<record>", file);
    } else if (ptrtype == BYTEVECTOR_TAG) {
      auto bv = (string_s *)(obj.value - PTR_TAG);
      fputs("#u8(", file);
      for (uint64_t i = 0; i < to_fixnum(bv->len); i++) {
        if (i != 0)
          fputc(' ', file);
        fprintf(file, "%" PRIu8, (uint8_t)bv->str[i]);
      }
      fputc(')', file);
    } else {
      fprintf(file, "PTR:%x", ptrtype);
    }
    break;
  }
  case VECTOR_TAG: {
    auto v = to_vector(obj);
    fputs("#(", file);
    for (uint64_t i = 0; i < to_fixnum(v->len); i++) {
      if (i != 0)
        fputc(' ', file);
      print_obj(v->v[i], file);
    }
    fputc(')', file);
    break;
  }
  case FLONUM_TAG: {
    auto f = to_flonum(obj);
    char *buffer = ftoa_fast(f->x);
    // Print it using only as many digits required as necessary, such
    // that the reader will read the same number back. printf can only
    // display a specific number of digits.
    // dtoa(f->x, buffer);
    fputs(buffer, file);
    free(buffer);
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
    string_s const *sym_name = get_sym_name(sym);
    if (sym_name) {
      fputs(sym_name->str, file);
    }
    break;
  }
  case CLOSURE_TAG: {
    closure_s const *clo = to_closure(obj);
    bcfunc const *func = to_func(clo->v[0]);
    fprintf(file, "#<procedure %s>", to_string(func->name)->str);
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
    } else if (obj.value == DEAD.value) {
      fputs("<dead>", file);
    } else {
      fprintf(file, "Unknown immediate: %" PRIx64 "\n", obj.value);
    }
    break;
  }
  default:
    break;
  }
}
