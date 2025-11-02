
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bc.h"
#include "types.h"

#define X(name, num) #name,
char *low_tag_names[] = {LOW_TAGS};

char *immediate_tag_names[] = {IMMEDIATE_TAGS};

char *ptr_tag_names[] = {PTR_TAGS};
#undef X
symbol *to_symbol(gc_obj obj) { return (symbol *)(obj.value - SYMBOL_TAG); }
closure_s *to_closure(gc_obj obj) {
  return (closure_s *)(obj.value - CLOSURE_TAG);
}
cont_s *to_cont(gc_obj obj) { return (cont_s *)(obj.value - PTR_TAG); }
// This one is not PTR, but anything!
void *to_raw_ptr(gc_obj obj) { return (void *)(obj.value & ~TAG_MASK); }
string_s *to_string(gc_obj obj) { return (string_s *)(obj.value - PTR_TAG); }
flonum_s *to_flonum(gc_obj obj) { return (flonum_s *)(obj.value - FLONUM_TAG); }
int64_t to_fixnum(gc_obj obj) { return obj.value >> 3; }
cons_s *to_cons(gc_obj obj) { return (cons_s *)(obj.value - CONS_TAG); }
vector_s *to_vector(gc_obj obj) { return (vector_s *)(obj.value - VECTOR_TAG); }
char to_char(gc_obj obj) { return (char)(obj.value >> 8); }
bc *to_return_address(gc_obj obj) { return obj.raddress; }
bcfunc *to_func(gc_obj obj) { return (bcfunc *)(obj.value - PTR_TAG); }

bcfunc const *closure_code_ptr(closure_s const *clo) {
  return (bcfunc *)clo->v[0].value;
}
string_s *get_sym_name(symbol *s) {
  return (string_s *)(s->name.value - PTR_TAG);
}
uint8_t get_tag(gc_obj obj) { return obj.value & TAG_MASK; }
uint8_t get_imm_tag(gc_obj obj) { return obj.value & IMMEDIATE_MASK; }
uint32_t get_ptr_tag(gc_obj obj) {
  return ((uint32_t *)(obj.value - PTR_TAG))[0];
}
bool is_char(gc_obj obj) { return get_imm_tag(obj) == CHAR_TAG; }
bool is_closure(gc_obj obj) { return get_tag(obj) == CLOSURE_TAG; }
bool is_cons(gc_obj obj) { return get_tag(obj) == CONS_TAG; }
bool is_ptr(gc_obj obj) { return get_tag(obj) == PTR_TAG; }
bool is_literal(gc_obj obj) { return get_tag(obj) == LITERAL_TAG; }
bool is_string(gc_obj obj) {
  return is_ptr(obj) && get_ptr_tag(obj) == STRING_TAG;
}
bool is_record(gc_obj obj) {
  return is_ptr(obj) && get_ptr_tag(obj) == RECORD_TAG;
}
bool is_undefined(gc_obj obj) { return get_imm_tag(obj) == UNDEFINED_TAG; }
bool is_vector(gc_obj obj) { return get_tag(obj) == VECTOR_TAG; }
bool is_symbol(gc_obj obj) { return get_tag(obj) == SYMBOL_TAG; }
bool is_flonum(gc_obj obj) { return get_tag(obj) == FLONUM_TAG; }
bool is_fixnum(gc_obj obj) { return get_tag(obj) == FIXNUM_TAG; }
bool is_func(gc_obj obj) { return is_ptr(obj) && get_ptr_tag(obj) == FUNC_TAG; }
bool is_heap_object(gc_obj obj) { return !is_fixnum(obj) && !is_literal(obj); }

// This is mostly a debug aid: The scheme-level printer is defined in
// scheme base code itself.
void print_obj(gc_obj obj, FILE *file) { //!OCLINT
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
    } else if (ptrtype == RECORD_TAG) {
      fputs("#<record>", file);
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
    // Print it using only as many digits required as necessary, such
    // that the reader will read the same number back. printf can only
    // display a specific number of digits.
    // dtoa(f->x, buffer);
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
    string_s const *sym_name = get_sym_name(sym);
    fputs(sym_name->str, file);
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
