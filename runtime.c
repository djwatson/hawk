#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <assert.h>
#ifdef __APPLE__
#include <crt_externs.h>
#endif
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bigint.h"
#include "ftoa.h"
#include "gc.h"
#include "hawk.h"
#include "runtime.h"
#include "types.h"

static bool fits_fixnum_i64(int64_t value) {
  return value >= FIXNUM_MIN_VALUE && value <= FIXNUM_MAX_VALUE;
}

static bool can_tag_fixnum_i64(int64_t value) {
  if (!fits_fixnum_i64(value)) {
    return false;
  }
  gc_obj tagged = tag_fixnum(value);
  return is_fixnum(tagged) && to_fixnum(tagged) == value;
}

static gc_obj normalize_exact_integer(gc_obj value) {
  if (!is_bignum(value)) {
    return value;
  }
  bn_i64_result_t i64 = bn_to_i64(to_bignum(value));
  if (i64.ok && can_tag_fixnum_i64(i64.value)) {
    return tag_fixnum(i64.value);
  }
  return value;
}

gc_obj SCM_MAKE_RECTANGULAR(gc_obj real, gc_obj imag) {
  gc_add_root((const void *)&real, 1, 0);
  gc_add_root((const void *)&imag, 1, 0);
  compnum_s *c = gc_alloc(sizeof(compnum_s));
  c->header.type = COMPNUM_TAG;
  c->real = real;
  c->imag = imag;
  gc_remove_root((const void *)&imag, 0);
  gc_remove_root((const void *)&real, 0);
  return tag_header(c, PTR_TAG);
}

gc_obj get_compnum(gc_obj v) {
  if (is_compnum(v)) {
    return v;
  }
  return SCM_MAKE_RECTANGULAR(v, tag_fixnum(0));
}

gc_obj SCM_REAL_PART(gc_obj comp) {
  return to_compnum(get_compnum(comp))->real;
}

gc_obj SCM_IMAG_PART(gc_obj comp) {
  return to_compnum(get_compnum(comp))->imag;
}

gc_obj vm_box_flonum(double x) {
  flonum_s *res = gc_alloc(sizeof(flonum_s));
  res->header.type = FLONUM_TAG;
  res->x = x;
  return tag_flonum(res);
}

double bignum_to_double(gc_obj v) {
  assert(is_bignum(v));
  bn_t *bn = to_bignum(v);
  bn_i64_result_t i64 = bn_to_i64(bn);
  if (i64.ok) {
    return (double)i64.value;
  }
  char *str = bn_to_string(bn, 10);
  if (!str) {
    abort();
  }
  double d = strtod(str, nullptr);
  free(str);
  return d;
}

gc_obj numeric_to_bignum_obj(gc_obj v) {
  if (is_bignum(v)) {
    return v;
  }
  if (is_fixnum(v)) {
    return tag_bignum(bn_from_i64(to_fixnum(v)));
  }
  abort();
}

int numeric_exact_compare(gc_obj v1, gc_obj v2) {
  gc_add_root((const void *)&v2, 1, 0);
  gc_obj b1 = numeric_to_bignum_obj(v1);
  gc_add_root((const void *)&b1, 1, 0);
  gc_obj b2 = numeric_to_bignum_obj(v2);
  int cmp = bn_cmp(to_bignum(b1), to_bignum(b2));
  gc_remove_root((const void *)&b1, 0);
  gc_remove_root((const void *)&v2, 0);
  return cmp;
}

double numeric_to_double(gc_obj v) {
  if (is_flonum(v)) {
    return to_flonum(v)->x;
  }
  if (is_fixnum(v)) {
    return (double)to_fixnum(v);
  }
  if (is_bignum(v)) {
    return bignum_to_double(v);
  }
  if (is_ratnum(v)) {
    ratnum_s *r = to_ratnum(v);
    return numeric_to_double(r->num) / numeric_to_double(r->denom);
  }
  abort();
}

static gc_obj pow2(int64_t exponent);
static gc_obj flonum_ratnum(double x);
static gc_obj tag_ratnum(ratnum_s r);
static ratnum_s get_ratnum(gc_obj v);
static int ratnum_cmp(ratnum_s a, ratnum_s b);

static gc_obj pow2(int64_t exponent) {
  gc_obj result = tag_fixnum(1);
  gc_obj base = tag_fixnum(2);
  gc_add_root((const void *)&result, 1, 0);
  gc_add_root((const void *)&base, 1, 0);
  while (exponent > 0) {
    if (exponent % 2 == 1) {
      result = vm_runtime_math_mul_slow(result, base);
    }
    base = vm_runtime_math_mul_slow(base, base);
    exponent /= 2;
  }
  gc_remove_root((const void *)&base, 0);
  gc_remove_root((const void *)&result, 0);
  return result;
}

static gc_obj flonum_ratnum(double x) {
  uint64_t bits;
  memcpy(&bits, &x, sizeof(bits));
  bool sign = bits >> 63;
  int64_t exponent = (int64_t)(bits >> 52 & 0x7ff);
  int64_t mantissa = (int64_t)(bits & 0xFFFFFFFFFFFFF);
  if (exponent != 0) {
    mantissa += 0x10000000000000;
  }
  gc_obj denom = tag_fixnum(0x10000000000000);
  exponent -= 1023;
  if (sign) {
    mantissa *= -1;
  }
  gc_obj numerator = tag_fixnum(mantissa);
  gc_add_root((const void *)&denom, 1, 0);
  gc_add_root((const void *)&numerator, 1, 0);
  if (exponent < 0) {
    exponent *= -1;
    denom = vm_runtime_math_mul_slow(denom, pow2(exponent));
  } else {
    numerator = vm_runtime_math_mul_slow(numerator, pow2(exponent));
  }

  gc_obj res = tag_ratnum(
      (ratnum_s){.header.type = RATNUM_TAG, .num = numerator, .denom = denom});
  gc_remove_root((const void *)&numerator, 0);
  gc_remove_root((const void *)&denom, 0);
  return res;
}

gc_obj numeric_inexact_value(gc_obj v) {
  if (is_fixnum(v)) {
    return vm_box_flonum((double)to_fixnum(v));
  }
  if (is_flonum(v)) {
    return v;
  }
  if (is_bignum(v)) {
    return vm_box_flonum(bignum_to_double(v));
  }
  if (is_ratnum(v)) {
    ratnum_s *r = to_ratnum(v);
    return vm_box_flonum(numeric_to_double(r->num) /
                         numeric_to_double(r->denom));
  }
  if (is_compnum(v)) {
    compnum_s *c = to_compnum(v);
    return SCM_MAKE_RECTANGULAR(numeric_inexact_value(c->real),
                                numeric_inexact_value(c->imag));
  }
  abort();
}

gc_obj numeric_exact_value(gc_obj v) {
  if (is_fixnum(v)) {
    return v;
  }
  if (is_bignum(v)) {
    return v;
  }
  if (is_ratnum(v)) {
    return v;
  }
  if (is_compnum(v)) {
    compnum_s *c = to_compnum(v);
    return SCM_MAKE_RECTANGULAR(numeric_exact_value(c->real),
                                numeric_exact_value(c->imag));
  }
  if (is_flonum(v)) {
    return flonum_ratnum(to_flonum(v)->x);
  }
  abort();
}

gc_obj numeric_truncate_value(gc_obj v) {
  if (is_fixnum(v)) {
    return v;
  }
  if (is_bignum(v)) {
    return v;
  }
  if (is_ratnum(v)) {
    ratnum_s *r = to_ratnum(v);
    gc_obj num = r->num;
    gc_obj denom = r->denom;
    gc_add_root((const void *)&num, 1, 0);
    gc_add_root((const void *)&denom, 1, 0);
    gc_obj res = vm_runtime_math_quotient_slow(num, denom);
    gc_remove_root((const void *)&denom, 0);
    gc_remove_root((const void *)&num, 0);
    return res;
  }
  if (is_flonum(v)) {
    return vm_box_flonum(trunc(to_flonum(v)->x));
  }
  abort();
}

bool numeric_fixnum_floatable_wlop(gc_obj v) {
  return is_fixnum(v) && llabs(to_fixnum(v)) <= (INT64_C(1) << 53);
}

static int numeric_exact_real_compare(gc_obj lhs, gc_obj rhs) {
  if (is_ratnum(lhs) || is_ratnum(rhs)) {
    ratnum_s l = get_ratnum(lhs);
    ratnum_s r = get_ratnum(rhs);
    return ratnum_cmp(l, r);
  }
  if ((is_fixnum(lhs) || is_bignum(lhs)) &&
      (is_fixnum(rhs) || is_bignum(rhs))) {
    return numeric_exact_compare(lhs, rhs);
  }
  abort();
}

// GC: may allocate via numeric_exact_value.
int numeric_real_compare(gc_obj lhs, gc_obj rhs, bool *ordered) {
  *ordered = true;
  if (is_compnum(lhs) || is_compnum(rhs)) {
    abort();
  }

  if (is_flonum(lhs) || is_flonum(rhs)) {
    double l = is_flonum(lhs) ? to_flonum(lhs)->x : 0.0;
    double r = is_flonum(rhs) ? to_flonum(rhs)->x : 0.0;
    if ((is_flonum(lhs) && isnan(l)) || (is_flonum(rhs) && isnan(r))) {
      *ordered = false;
      return 0;
    }
    if (is_flonum(lhs) && is_flonum(rhs)) {
      return (l > r) - (l < r);
    }
    // Chez-style fast path: compare inexactly only when the exact fixnum is
    // represented by a double without loss. Larger exacts must exactify the
    // flonum to preserve comparison transitivity.
    if ((is_flonum(lhs) && numeric_fixnum_floatable_wlop(rhs)) ||
        (is_flonum(rhs) && numeric_fixnum_floatable_wlop(lhs))) {
      double ld = is_flonum(lhs) ? l : (double)to_fixnum(lhs);
      double rd = is_flonum(rhs) ? r : (double)to_fixnum(rhs);
      return (ld > rd) - (ld < rd);
    }
    if (is_flonum(lhs) && isinf(l)) {
      return l < 0.0 ? -1 : 1;
    }
    if (is_flonum(rhs) && isinf(r)) {
      return r < 0.0 ? 1 : -1;
    }

    gc_add_root((const void *)&rhs, 1, 0);
    gc_obj exact_lhs = numeric_exact_value(lhs);
    gc_add_root((const void *)&exact_lhs, 1, 0);
    gc_obj exact_rhs = numeric_exact_value(rhs);
    gc_add_root((const void *)&exact_rhs, 1, 0);
    int cmp = numeric_exact_real_compare(exact_lhs, exact_rhs);
    gc_remove_root((const void *)&exact_rhs, 0);
    gc_remove_root((const void *)&exact_lhs, 0);
    gc_remove_root((const void *)&rhs, 0);
    return cmp;
  }

  return numeric_exact_real_compare(lhs, rhs);
}

bool numeric_eqv(gc_obj lhs, gc_obj rhs) {
  // Numeric = semantics: NaNs are unordered and never equal here.
  if (is_compnum(lhs) || is_compnum(rhs)) {
    compnum_s *l = is_compnum(lhs) ? to_compnum(lhs) : nullptr;
    compnum_s *r = is_compnum(rhs) ? to_compnum(rhs) : nullptr;
    gc_obj lreal = l ? l->real : lhs;
    gc_obj limag = l ? l->imag : tag_fixnum(0);
    gc_obj rreal = r ? r->real : rhs;
    gc_obj rimag = r ? r->imag : tag_fixnum(0);
    return numeric_eqv(lreal, rreal) && numeric_eqv(limag, rimag);
  }
  bool ordered;
  return numeric_real_compare(lhs, rhs, &ordered) == 0 && ordered;
}

bool obj_jeqv(gc_obj lhs, gc_obj rhs) {
  // Object eqv?: identity first, then Chez-style numeric eqv? for numbers.
  if (lhs.value == rhs.value) {
    return true;
  }
  if (get_type_tag(lhs) != get_type_tag(rhs)) {
    return false;
  }
  if (is_compnum(lhs) || is_compnum(rhs)) {
    compnum_s *l = is_compnum(lhs) ? to_compnum(lhs) : nullptr;
    compnum_s *r = is_compnum(rhs) ? to_compnum(rhs) : nullptr;
    gc_obj lreal = l ? l->real : lhs;
    gc_obj limag = l ? l->imag : tag_fixnum(0);
    gc_obj rreal = r ? r->real : rhs;
    gc_obj rimag = r ? r->imag : tag_fixnum(0);
    return obj_jeqv(lreal, rreal) && obj_jeqv(limag, rimag);
  }
  if (is_flonum(lhs) && is_flonum(rhs)) {
    // Scheme eqv? semantics, matching Chez: NaNs are eqv?, otherwise bits.
    double l = to_flonum(lhs)->x;
    double r = to_flonum(rhs)->x;
    if (isnan(l) || isnan(r)) {
      return isnan(l) && isnan(r);
    }
    return memcmp(&l, &r, sizeof(l)) == 0;
  }
  if ((is_fixnum(lhs) || is_flonum(lhs) || is_bignum(lhs) || is_ratnum(lhs) ||
       is_compnum(lhs)) &&
      (is_fixnum(rhs) || is_flonum(rhs) || is_bignum(rhs) || is_ratnum(rhs) ||
       is_compnum(rhs))) {
    return numeric_eqv(lhs, rhs);
  }
  return lhs.value == rhs.value;
}

static size_t runtime_align_words(size_t bytes) {
  return (bytes + sizeof(gc_obj) - 1) & ~(sizeof(gc_obj) - 1);
}

static int64_t runtime_timespec_nsecs(struct timespec ts) {
  return (ts.tv_sec * INT64_C(1000000000)) + ts.tv_nsec;
}

EXPORT int64_t scm_current_jiffy(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    abort();
  }
  return runtime_timespec_nsecs(ts);
}

EXPORT double scm_current_second(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
    abort();
  }
  return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

static uint64_t runtime_list_length(gc_obj list) {
  uint64_t len = 0;
  while (list.value != NIL_TAG) {
    if (!is_cons(list)) {
      abort();
    }
    len++;
    list = to_cons(list)->b;
  }
  return len;
}

static int64_t runtime_expect_fixnum(gc_obj obj) {
  if (!is_fixnum(obj)) {
    abort();
  }
  return to_fixnum(obj);
}

static vector_s *runtime_expect_vector(gc_obj obj, int64_t len) {
  if (!is_vector(obj)) {
    abort();
  }
  vector_s *vec = to_vector(obj);
  if (to_fixnum(vec->len) != len) {
    abort();
  }
  return vec;
}

static bool runtime_symbol_eq(gc_obj obj, const char *name) {
  if (!is_symbol(obj)) {
    return false;
  }
  string_s const *sym_name = get_sym_name(to_symbol(obj));
  return sym_name && strcmp(sym_name->str, name) == 0;
}

static bool runtime_decode_fun_ref(gc_obj obj, uint64_t fun_count,
                                   uint64_t *out_id) {
  if (!is_vector(obj)) {
    return false;
  }
  vector_s *vec = to_vector(obj);
  if (to_fixnum(vec->len) != 2 || !runtime_symbol_eq(vec->v[0], "fun-ref")) {
    return false;
  }
  int64_t id = runtime_expect_fixnum(vec->v[1]);
  if (id < 0 || (uint64_t)id >= fun_count) {
    abort();
  }
  *out_id = (uint64_t)id;
  return true;
}

static bool runtime_decode_closure_ref(gc_obj obj, uint64_t fun_count,
                                       uint64_t *out_id) {
  if (!is_vector(obj)) {
    return false;
  }
  vector_s *vec = to_vector(obj);
  if (to_fixnum(vec->len) != 2 ||
      !runtime_symbol_eq(vec->v[0], "closure-ref")) {
    return false;
  }
  int64_t id = runtime_expect_fixnum(vec->v[1]);
  if (id < 0 || (uint64_t)id >= fun_count) {
    abort();
  }
  *out_id = (uint64_t)id;
  return true;
}

EXPORT gc_obj scm_emit_bitcode_closure(gc_obj payload) {
  LOG(gc, "scm_emit_bitcode_closure");
  gc_add_root((const void *)&payload, 1, 0);
  vector_s *root = runtime_expect_vector(payload, 2);
  gc_obj entry_id_obj = root->v[0];
  gc_obj funs_list = root->v[1];
  gc_add_root((const void *)&funs_list, 1, 0);
  uint64_t fun_count = runtime_list_length(funs_list);
  int64_t entry_id_i64 = runtime_expect_fixnum(entry_id_obj);
  if (entry_id_i64 < 0 || (uint64_t)entry_id_i64 >= fun_count) {
    abort();
  }
  uint64_t entry_id = (uint64_t)entry_id_i64;

  gc_obj *funcs = calloc(fun_count, sizeof(*funcs));
  if (!funcs) {
    abort();
  }
  gc_add_root((const void *)funcs, fun_count, 0);

  gc_obj first_cur = funs_list;
  gc_add_root((const void *)&first_cur, 1, 0);
  while (first_cur.value != NIL_TAG) {
    gc_obj cur = first_cur;
    vector_s *desc = runtime_expect_vector(to_cons(cur)->a, 4);
    int64_t id_i64 = runtime_expect_fixnum(desc->v[0]);
    if (id_i64 < 0 || (uint64_t)id_i64 >= fun_count) {
      abort();
    }
    uint64_t id = (uint64_t)id_i64;
    if (funcs[id].value != 0) {
      abort();
    }
    uint64_t const_cnt = runtime_list_length(desc->v[2]);
    uint64_t bc_cnt = runtime_list_length(desc->v[3]);
    size_t bytes = runtime_align_words(
        sizeof(bcfunc) + (const_cnt * sizeof(gc_obj)) + (bc_cnt * sizeof(bc)));
    bcfunc *func = gc_alloc(bytes);
    func->poly_cnt = 0;
    func->downrec_ok = 0;
    func->name = NIL;
    func->const_cnt = const_cnt;
    func->bc_cnt = bc_cnt;
    memset(func->data, 0, const_cnt * sizeof(gc_obj));
    func->header.type = FUNC_TAG;
    funcs[id] = tag_func(func);
    first_cur = to_cons(first_cur)->b;
  }
  gc_remove_root((const void *)&first_cur, 0);
  for (uint64_t i = 0; i < fun_count; i++) {
    if (funcs[i].value == 0) {
      abort();
    }
  }

  gc_obj cur = funs_list;
  gc_add_root((const void *)&cur, 1, 0);
  while (cur.value != NIL_TAG) {
    gc_obj desc_obj = to_cons(cur)->a;
    gc_add_root((const void *)&desc_obj, 1, 0);
    vector_s *desc = runtime_expect_vector(desc_obj, 4);
    uint64_t id = (uint64_t)runtime_expect_fixnum(desc->v[0]);
    bcfunc *func = (bcfunc *)to_gc_header(funcs[id]);
    func->name = desc->v[1];

    gc_obj *consts = (gc_obj *)func->data;
    uint64_t const_idx = 0;
    gc_obj c = desc->v[2];
    gc_add_root((const void *)&c, 1, 0);
    while (c.value != NIL_TAG) {
      gc_obj raw = to_cons(c)->a;
      uint64_t ref_id;
      gc_obj val;
      if (runtime_decode_fun_ref(raw, fun_count, &ref_id)) {
        val = funcs[ref_id];
      } else if (runtime_decode_closure_ref(raw, fun_count, &ref_id)) {
        closure_s *clo = gc_alloc(sizeof(closure_s) + sizeof(gc_obj));
        clo->header.type = CLOSURE_TAG;
        clo->len = tag_fixnum(1);
        clo->v[0] = funcs[ref_id];
        val = tag_closure(clo);
      } else {
        val = raw;
      }
      consts[const_idx] = val;
      const_idx++;
      c = to_cons(c)->b;
    }
    gc_remove_root((const void *)&c, 0);
    gc_register_bcfunc(func);

    desc = runtime_expect_vector(to_cons(cur)->a, 4);
    bc *code = (bc *)(func->data + (func->const_cnt * sizeof(gc_obj)));
    uint64_t code_idx = 0;
    for (gc_obj w = desc->v[3]; w.value != NIL_TAG; w = to_cons(w)->b) {
      int64_t word = runtime_expect_fixnum(to_cons(w)->a);
      if (word < 0 || (uint64_t)word > UINT32_MAX) {
        abort();
      }
      code[code_idx++].full_data = (uint32_t)word;
    }
    gc_remove_root((const void *)&desc_obj, 0);
    cur = to_cons(cur)->b;
  }
  gc_remove_root((const void *)&cur, 0);

  closure_s *clo = gc_alloc(sizeof(closure_s) + sizeof(gc_obj));
  clo->header.type = CLOSURE_TAG;
  clo->len = tag_fixnum(1);
  clo->v[0] = funcs[entry_id];
  gc_obj out = tag_closure(clo);

  gc_remove_root((const void *)funcs, 0);
  free(funcs);
  gc_remove_root((const void *)&funs_list, 0);
  gc_remove_root((const void *)&payload, 0);
  LOG(gc, "scm_emit_bitcode_closure done");
  return out;
}

// GC: may allocate via gc_alloc.
static gc_obj make_cons(gc_obj a, gc_obj b) {
  gc_add_root((const void *)&a, 1, 0);
  gc_add_root((const void *)&b, 1, 0);
  cons_s *cell = gc_alloc(sizeof(cons_s));
  cell->header.type = CONS_TAG;
  cell->a = a;
  cell->b = b;
  gc_remove_root((const void *)&b, 0);
  gc_remove_root((const void *)&a, 0);
  return tag_cons(cell);
}

// GC: may allocate via gc_alloc.
gc_obj make_string(const char *str) {
  size_t len = strlen(str);
  size_t bytes = (sizeof(string_s) + len + 1 + 7) & ~(size_t)7;
  string_s *out = gc_alloc((uint64_t)bytes);
  out->header.type = STRING_TAG;
  out->len = tag_fixnum((int64_t)len);
  memcpy(out->str, str, len + 1);
  return tag_string(out);
}

// GC: may allocate via gc_alloc.
gc_obj make_string_list(char **strs, size_t len) {
  gc_obj head = NIL;
  gc_add_root((const void *)&head, 1, 0);
  for (size_t i = len; i > 0; i--) {
    gc_obj str = make_string(strs[i - 1]);
    head = make_cons(str, head);
  }
  gc_remove_root((const void *)&head, 0);
  return head;
}

// GC: may allocate via gc_alloc.
EXPORT gc_obj SCM_COMMAND_LINE() {
  gc_obj head = NIL;
  gc_add_root((const void *)&head, 1, 0);
  for (int i = command_line_argc - 1; i >= 0; i--) {
    gc_obj arg = make_string(command_line_argv[i]);
    head = make_cons(arg, head);
  }

  gc_remove_root((const void *)&head, 0);
  return head;
}

EXPORT gc_obj SCM_LISTP(gc_obj x) {
  gc_obj fast = x;
  gc_obj slow = x;

  while (true) {
    if (fast.value == NIL_TAG) {
      return TRUE_REP;
    }
    if (!is_cons(fast)) {
      return FALSE_REP;
    }
    fast = to_cons(fast)->b;

    if (fast.value == NIL_TAG) {
      return TRUE_REP;
    }
    if (!is_cons(fast)) {
      return FALSE_REP;
    }
    fast = to_cons(fast)->b;
    slow = to_cons(slow)->b;
    if (fast.value == slow.value) {
      return FALSE_REP;
    }
  }
}

EXPORT gc_obj SCM_LENGTH(gc_obj list) {
  uint64_t len = runtime_list_length(list);
  if (len > (uint64_t)FIXNUM_MAX_VALUE) {
    abort();
  }
  return tag_fixnum((int64_t)len);
}

static gc_obj runtime_assoc(gc_obj obj, gc_obj alist, bool eqv) {
  gc_add_root((const void *)&obj, 1, 0);
  gc_add_root((const void *)&alist, 1, 0);
  while (alist.value != NIL_TAG) {
    if (!is_cons(alist)) {
      abort();
    }
    auto list = to_cons(alist);
    gc_obj entry = list->a;
    if (!is_cons(entry)) {
      abort();
    }
    gc_obj key = to_cons(entry)->a;
    bool match;
    if (eqv) {
      gc_add_root((const void *)&entry, 1, 0);
      match = obj_jeqv(key, obj);
      gc_remove_root((const void *)&entry, 0);
    } else {
      match = key.value == obj.value;
    }
    if (match) {
      gc_remove_root((const void *)&alist, 0);
      gc_remove_root((const void *)&obj, 0);
      return entry;
    }
    alist = to_cons(alist)->b;
  }
  gc_remove_root((const void *)&alist, 0);
  gc_remove_root((const void *)&obj, 0);
  return FALSE_REP;
}

EXPORT gc_obj SCM_ASSQ(gc_obj obj, gc_obj alist) {
  return runtime_assoc(obj, alist, false);
}

EXPORT gc_obj SCM_ASSV(gc_obj obj, gc_obj alist) {
  return runtime_assoc(obj, alist, true);
}

static bool exact_is_negative(gc_obj v) {
  if (is_fixnum(v)) {
    return to_fixnum(v) < 0;
  }
  if (is_bignum(v)) {
    return bn_is_negative(to_bignum(v));
  }
  abort();
}

// GC: may allocate via gc_alloc through vm_runtime_math_mul_slow.
static gc_obj exact_abs(gc_obj v) {
  if (!exact_is_negative(v)) {
    return v;
  }
  return vm_runtime_math_mul_slow(v, tag_fixnum(-1));
}

// GC: may allocate via gc_alloc through vm_runtime_math_mod_slow and exact_abs.
static gc_obj exact_gcd(gc_obj a, gc_obj b) {
  while (!numeric_is_zero(b)) {
    gc_add_root((const void *)&b, 1, 0);
    gc_obj r = vm_runtime_math_mod_slow(a, b);
    gc_remove_root((const void *)&b, 0);
    a = b;
    b = r;
  }
  return exact_abs(a);
}

static ratnum_s get_ratnum(gc_obj v) {
  if (is_ratnum(v)) {
    return *to_ratnum(v);
  }
  if (is_fixnum(v) || is_bignum(v)) {
    return (ratnum_s){
        .header.type = RATNUM_TAG,
        .num = v,
        .denom = tag_fixnum(1),
    };
  }
  abort();
}

// GC: may allocate via gc_alloc.
static gc_obj tag_ratnum(ratnum_s r) {
  gc_obj a = r.num;
  gc_obj b = r.denom;
  gc_add_root((const void *)&a, 1, 0);
  gc_add_root((const void *)&b, 1, 0);
  if (numeric_is_zero(b)) {
    gc_remove_root((const void *)&b, 0);
    gc_remove_root((const void *)&a, 0);
    abort();
  }
  bool neg = exact_is_negative(a) ^ exact_is_negative(b);
  a = exact_abs(a);
  b = exact_abs(b);
  if (numeric_is_zero(a)) {
    gc_remove_root((const void *)&b, 0);
    gc_remove_root((const void *)&a, 0);
    return a;
  }
  gc_obj g = exact_gcd(a, b);
  if (!(is_fixnum(g) && to_fixnum(g) == 1)) {
    gc_add_root((const void *)&g, 1, 0);
    a = vm_runtime_math_quotient_slow(a, g);
    b = vm_runtime_math_quotient_slow(b, g);
    gc_remove_root((const void *)&g, 0);
  }
  if (is_fixnum(b) && to_fixnum(b) == 1) {
    gc_obj res = a;
    if (neg) {
      res = vm_runtime_math_mul_slow(tag_fixnum(-1), a);
    }
    gc_remove_root((const void *)&b, 0);
    gc_remove_root((const void *)&a, 0);
    return res;
  }
  if (neg) {
    a = vm_runtime_math_mul_slow(tag_fixnum(-1), a);
  }
  ratnum_s *res = gc_alloc(sizeof(ratnum_s));
  res->header.type = RATNUM_TAG;
  res->num = a;
  res->denom = b;
  gc_remove_root((const void *)&b, 0);
  gc_remove_root((const void *)&a, 0);
  return tag_header(res, PTR_TAG);
}

// GC: may allocate via gc_alloc through vm_runtime_math_*_slow.
static ratnum_s ratnum_add(ratnum_s a, ratnum_s b) {
  gc_add_root((const void *)&a.denom, 1, 0);
  gc_add_root((const void *)&b.denom, 1, 0);
  gc_obj p1 = vm_runtime_math_mul_slow(a.num, b.denom);
  gc_add_root((const void *)&p1, 1, 0);
  gc_obj denom = vm_runtime_math_mul_slow(a.denom, b.denom);
  gc_obj p2 = vm_runtime_math_mul_slow(b.num, a.denom);
  gc_obj num = vm_runtime_math_add_slow(p1, p2);
  gc_remove_root((const void *)&p1, 0);
  gc_remove_root((const void *)&b.denom, 0);
  gc_remove_root((const void *)&a.denom, 0);
  return (ratnum_s){
      .header.type = RATNUM_TAG,
      .num = num,
      .denom = denom,
  };
}

// GC: may allocate via gc_alloc through vm_runtime_math_*_slow.
static ratnum_s ratnum_sub(ratnum_s a, ratnum_s b) {
  gc_add_root((const void *)&a.denom, 1, 0);
  gc_add_root((const void *)&b.denom, 1, 0);
  gc_obj p1 = vm_runtime_math_mul_slow(a.num, b.denom);
  gc_add_root((const void *)&p1, 1, 0);
  gc_obj denom = vm_runtime_math_mul_slow(a.denom, b.denom);
  gc_obj p2 = vm_runtime_math_mul_slow(b.num, a.denom);
  gc_obj num = vm_runtime_math_sub_slow(p1, p2);
  gc_remove_root((const void *)&p1, 0);
  gc_remove_root((const void *)&b.denom, 0);
  gc_remove_root((const void *)&a.denom, 0);
  return (ratnum_s){
      .header.type = RATNUM_TAG,
      .num = num,
      .denom = denom,
  };
}

// GC: may allocate via gc_alloc through vm_runtime_math_*_slow.
static ratnum_s ratnum_mul(ratnum_s a, ratnum_s b) {
  gc_add_root((const void *)&a.denom, 1, 0);
  gc_add_root((const void *)&b.denom, 1, 0);
  gc_obj denom = vm_runtime_math_mul_slow(a.denom, b.denom);
  gc_obj num = vm_runtime_math_mul_slow(a.num, b.num);
  gc_remove_root((const void *)&b.denom, 0);
  gc_remove_root((const void *)&a.denom, 0);
  return (ratnum_s){
      .header.type = RATNUM_TAG,
      .num = num,
      .denom = denom,
  };
}

// GC: may allocate via gc_alloc through vm_runtime_math_*_slow.
static ratnum_s ratnum_div(ratnum_s a, ratnum_s b) {
  gc_add_root((const void *)&a.num, 1, 0);
  gc_add_root((const void *)&b.denom, 1, 0);
  gc_obj denom = vm_runtime_math_mul_slow(a.denom, b.num);
  gc_obj num = vm_runtime_math_mul_slow(a.num, b.denom);
  gc_remove_root((const void *)&b.denom, 0);
  gc_remove_root((const void *)&a.num, 0);
  return (ratnum_s){
      .header.type = RATNUM_TAG,
      .num = num,
      .denom = denom,
  };
}

// GC: may allocate via gc_alloc through vm_runtime_math_mul_slow.
static int ratnum_cmp(ratnum_s a, ratnum_s b) {
  gc_add_root((const void *)&a.denom, 1, 0);
  gc_add_root((const void *)&b.num, 1, 0);
  gc_obj left = vm_runtime_math_mul_slow(a.num, b.denom);
  gc_add_root((const void *)&left, 1, 0);
  gc_obj right = vm_runtime_math_mul_slow(b.num, a.denom);
  int cmp = numeric_exact_compare(left, right);
  gc_remove_root((const void *)&left, 0);
  gc_remove_root((const void *)&b.num, 0);
  gc_remove_root((const void *)&a.denom, 0);
  return cmp;
}

INLINE inline static bool double_part(gc_obj v, double *out, bool *inexact) {
  if (is_flonum(v)) {
    *out = to_flonum(v)->x;
    *inexact = true;
    return true;
  }
  if (is_fixnum(v)) {
    *out = (double)to_fixnum(v);
    return true;
  }
  return false;
}

INLINE inline static bool compnum_double_parts(gc_obj v, double *real,
                                               double *imag, bool *inexact) {
  if (is_compnum(v)) {
    compnum_s *c = to_compnum(v);
    return double_part(c->real, real, inexact) &&
           double_part(c->imag, imag, inexact);
  }
  *imag = 0.0;
  return double_part(v, real, inexact);
}

// GC: may allocate via gc_alloc through vm_box_flonum and SCM_MAKE_RECTANGULAR.
static gc_obj make_inexact_compnum(double real, double imag) {
  gc_obj real_obj = vm_box_flonum(real);
  gc_add_root((const void *)&real_obj, 1, 0);
  gc_obj imag_obj = vm_box_flonum(imag);
  gc_obj out = SCM_MAKE_RECTANGULAR(real_obj, imag_obj);
  gc_remove_root((const void *)&real_obj, 0);
  return out;
}

// GC: may allocate via gc_alloc through get_compnum, vm_runtime_math_add_slow,
// and normalize_compnum.
static gc_obj compnum_add(gc_obj a, gc_obj b) {
  double ar;
  double ai;
  double br;
  double bi;
  bool inexact = false;
  if (compnum_double_parts(a, &ar, &ai, &inexact) &&
      compnum_double_parts(b, &br, &bi, &inexact) && inexact) {
    return make_inexact_compnum(ar + br, ai + bi);
  }
  gc_add_root((const void *)&b, 1, 0);
  gc_obj ca_obj = get_compnum(a);
  gc_add_root((const void *)&ca_obj, 1, 0);
  gc_obj cb_obj = get_compnum(b);
  gc_add_root((const void *)&cb_obj, 1, 0);
  gc_obj real = vm_runtime_math_add_slow(to_compnum(ca_obj)->real,
                                         to_compnum(cb_obj)->real);
  gc_add_root((const void *)&real, 1, 0);
  gc_obj imag = vm_runtime_math_add_slow(to_compnum(ca_obj)->imag,
                                         to_compnum(cb_obj)->imag);
  gc_obj out = SCM_MAKE_RECTANGULAR(real, imag);
  gc_remove_root((const void *)&real, 0);
  gc_remove_root((const void *)&cb_obj, 0);
  gc_remove_root((const void *)&ca_obj, 0);
  gc_remove_root((const void *)&b, 0);
  return out;
}

// GC: may allocate via gc_alloc through get_compnum, vm_runtime_math_sub_slow,
// and normalize_compnum.
static gc_obj compnum_sub(gc_obj a, gc_obj b) {
  double ar;
  double ai;
  double br;
  double bi;
  bool inexact = false;
  if (compnum_double_parts(a, &ar, &ai, &inexact) &&
      compnum_double_parts(b, &br, &bi, &inexact) && inexact) {
    return make_inexact_compnum(ar - br, ai - bi);
  }
  gc_add_root((const void *)&b, 1, 0);
  gc_obj ca_obj = get_compnum(a);
  gc_add_root((const void *)&ca_obj, 1, 0);
  gc_obj cb_obj = get_compnum(b);
  gc_add_root((const void *)&cb_obj, 1, 0);
  gc_obj real = vm_runtime_math_sub_slow(to_compnum(ca_obj)->real,
                                         to_compnum(cb_obj)->real);
  gc_add_root((const void *)&real, 1, 0);
  gc_obj imag = vm_runtime_math_sub_slow(to_compnum(ca_obj)->imag,
                                         to_compnum(cb_obj)->imag);
  gc_obj out = SCM_MAKE_RECTANGULAR(real, imag);
  gc_remove_root((const void *)&real, 0);
  gc_remove_root((const void *)&cb_obj, 0);
  gc_remove_root((const void *)&ca_obj, 0);
  gc_remove_root((const void *)&b, 0);
  return out;
}

// GC: may allocate via gc_alloc through get_compnum and vm_runtime_math_*_slow.
static gc_obj compnum_mul(gc_obj a, gc_obj b) {
  double ar;
  double ai;
  double br;
  double bi;
  bool inexact = false;
  if (compnum_double_parts(a, &ar, &ai, &inexact) &&
      compnum_double_parts(b, &br, &bi, &inexact) && inexact) {
    return make_inexact_compnum((ar * br) - (ai * bi), (ar * bi) + (ai * br));
  }
  gc_add_root((const void *)&b, 1, 0);
  gc_obj ca_obj = get_compnum(a);
  gc_add_root((const void *)&ca_obj, 1, 0);
  gc_obj cb_obj = get_compnum(b);
  gc_add_root((const void *)&cb_obj, 1, 0);
  gc_obj left = vm_runtime_math_mul_slow(to_compnum(ca_obj)->real,
                                         to_compnum(cb_obj)->real);
  gc_add_root((const void *)&left, 1, 0);
  gc_obj right = vm_runtime_math_mul_slow(to_compnum(ca_obj)->imag,
                                          to_compnum(cb_obj)->imag);
  gc_obj real = vm_runtime_math_sub_slow(left, right);
  gc_remove_root((const void *)&left, 0);
  gc_add_root((const void *)&real, 1, 0);

  left = vm_runtime_math_mul_slow(to_compnum(ca_obj)->real,
                                  to_compnum(cb_obj)->imag);
  gc_add_root((const void *)&left, 1, 0);
  right = vm_runtime_math_mul_slow(to_compnum(ca_obj)->imag,
                                   to_compnum(cb_obj)->real);
  gc_obj imag = vm_runtime_math_add_slow(left, right);
  gc_remove_root((const void *)&left, 0);

  gc_obj out = SCM_MAKE_RECTANGULAR(real, imag);
  gc_remove_root((const void *)&real, 0);
  gc_remove_root((const void *)&cb_obj, 0);
  gc_remove_root((const void *)&ca_obj, 0);
  gc_remove_root((const void *)&b, 0);
  return out;
}

// GC: may allocate via gc_alloc through get_compnum and vm_runtime_math_*_slow.
static gc_obj compnum_div(gc_obj a, gc_obj b) {
  gc_add_root((const void *)&b, 1, 0);
  gc_obj ca_obj = get_compnum(a);
  gc_add_root((const void *)&ca_obj, 1, 0);
  gc_obj cb_obj = get_compnum(b);
  gc_add_root((const void *)&cb_obj, 1, 0);

  if (numeric_is_zero(to_compnum(cb_obj)->imag)) {
    if (numeric_is_zero(to_compnum(cb_obj)->real)) {
      abort();
    }
    gc_obj real = vm_runtime_math_div_slow(to_compnum(ca_obj)->real,
                                           to_compnum(cb_obj)->real);
    gc_add_root((const void *)&real, 1, 0);
    gc_obj imag = vm_runtime_math_div_slow(to_compnum(ca_obj)->imag,
                                           to_compnum(cb_obj)->real);
    gc_obj out = SCM_MAKE_RECTANGULAR(real, imag);
    gc_remove_root((const void *)&real, 0);
    gc_remove_root((const void *)&cb_obj, 0);
    gc_remove_root((const void *)&ca_obj, 0);
    gc_remove_root((const void *)&b, 0);
    return out;
  }

  gc_obj c2 = vm_runtime_math_mul_slow(to_compnum(cb_obj)->real,
                                       to_compnum(cb_obj)->real);
  gc_add_root((const void *)&c2, 1, 0);
  gc_obj d2 = vm_runtime_math_mul_slow(to_compnum(cb_obj)->imag,
                                       to_compnum(cb_obj)->imag);

  gc_obj denom = vm_runtime_math_add_slow(c2, d2);
  gc_remove_root((const void *)&c2, 0);
  gc_add_root((const void *)&denom, 1, 0);
  if (numeric_is_zero(denom)) {
    abort();
  }

  gc_obj left = vm_runtime_math_mul_slow(to_compnum(ca_obj)->real,
                                         to_compnum(cb_obj)->real);
  gc_add_root((const void *)&left, 1, 0);
  gc_obj right = vm_runtime_math_mul_slow(to_compnum(ca_obj)->imag,
                                          to_compnum(cb_obj)->imag);
  gc_obj real_num = vm_runtime_math_add_slow(left, right);
  gc_remove_root((const void *)&left, 0);
  gc_obj real = vm_runtime_math_div_slow(real_num, denom);
  gc_add_root((const void *)&real, 1, 0);

  left = vm_runtime_math_mul_slow(to_compnum(ca_obj)->imag,
                                  to_compnum(cb_obj)->real);
  gc_add_root((const void *)&left, 1, 0);
  right = vm_runtime_math_mul_slow(to_compnum(ca_obj)->real,
                                   to_compnum(cb_obj)->imag);
  gc_obj imag_num = vm_runtime_math_sub_slow(left, right);
  gc_remove_root((const void *)&left, 0);
  gc_obj imag = vm_runtime_math_div_slow(imag_num, denom);
  gc_obj out = SCM_MAKE_RECTANGULAR(real, imag);

  gc_remove_root((const void *)&real, 0);
  gc_remove_root((const void *)&denom, 0);
  gc_remove_root((const void *)&cb_obj, 0);
  gc_remove_root((const void *)&ca_obj, 0);
  gc_remove_root((const void *)&b, 0);
  return out;
}

EXPORT int32_t scm_open(char *name, uint8_t readonly) {
  return open(name, readonly ? O_RDONLY : O_WRONLY | O_CREAT | O_TRUNC, 0777);
}

EXPORT char *flonum_string(double d) { return ftoa_fast(d); }
EXPORT char *bignum_string(gc_obj g) {
  assert(is_bignum(g));
  return bn_to_string(to_bignum(g), 10);
}

// GC: may allocate via gc_alloc through make_cons.
EXPORT gc_obj bignum_exact_integer_sqrt(gc_obj g) {
  assert(is_bignum(g));
  bn_sqrt_result_t qr = bn_sqrt(to_bignum(g));
  return make_cons(normalize_exact_integer(tag_bignum(qr.q)),
                   normalize_exact_integer(tag_bignum(qr.r)));
}

// GC: may allocate via gc_alloc through vm_box_flonum, tag_ratnum, and
// compnum_* helpers.
#define DEFINE_VM_RUNTIME_OVERFLOW_SLOW(name, oplcname, op, shift)             \
  gc_obj vm_runtime_math_##name##_slow(gc_obj v1, gc_obj v2) {                 \
    if (is_compnum(v1) || is_compnum(v2)) {                                    \
      return compnum_##oplcname(v1, v2);                                       \
    }                                                                          \
    if (is_flonum(v1) || is_flonum(v2)) {                                      \
      return vm_box_flonum(op(numeric_to_double(v1), numeric_to_double(v2)));  \
    }                                                                          \
    if (is_ratnum(v1) || is_ratnum(v2)) {                                      \
      ratnum_s r1 = get_ratnum(v1);                                            \
      ratnum_s r2 = get_ratnum(v2);                                            \
      return tag_ratnum(ratnum_##oplcname(r1, r2));                            \
    }                                                                          \
    if (is_fixnum(v1) && is_fixnum(v2)) {                                      \
      gc_obj res;                                                              \
      if (!__builtin_##oplcname##_overflow(v1.value, shift(v2.value),          \
                                           &res.value)) {                      \
        return res;                                                            \
      }                                                                        \
    }                                                                          \
    gc_add_root((const void *)&v2, 1, 0);                                      \
    gc_obj b1 = numeric_to_bignum_obj(v1);                                     \
    gc_add_root((const void *)&b1, 1, 0);                                      \
    gc_obj b2 = numeric_to_bignum_obj(v2);                                     \
    gc_add_root((const void *)&b2, 1, 0);                                      \
    gc_obj res = normalize_exact_integer(                                      \
        tag_bignum(bn_##oplcname(to_bignum(b1), to_bignum(b2))));              \
    gc_remove_root((const void *)&b2, 0);                                      \
    gc_remove_root((const void *)&b1, 0);                                      \
    gc_remove_root((const void *)&v2, 0);                                      \
    return res;                                                                \
  }

DEFINE_VM_RUNTIME_OVERFLOW_SLOW(add, add, VM_MATH_ADD, VM_MATH_NOSHIFT)
DEFINE_VM_RUNTIME_OVERFLOW_SLOW(sub, sub, VM_MATH_SUB, VM_MATH_NOSHIFT)
DEFINE_VM_RUNTIME_OVERFLOW_SLOW(mul, mul, VM_MATH_MUL, VM_MATH_SHIFT)

#undef DEFINE_VM_RUNTIME_OVERFLOW_SLOW

// GC: may allocate via gc_alloc through vm_box_flonum, compnum_div, and
// tag_ratnum.
gc_obj vm_runtime_math_div_slow(gc_obj v1, gc_obj v2) {
  if (is_compnum(v1) || is_compnum(v2)) {
    return compnum_div(v1, v2);
  }
  if (numeric_is_zero(v2)) {
    abort();
  }
  if (is_flonum(v1) || is_flonum(v2)) {
    return vm_box_flonum(numeric_to_double(v1) / numeric_to_double(v2));
  }
  ratnum_s r1 = get_ratnum(v1);
  ratnum_s r2 = get_ratnum(v2);
  return tag_ratnum(ratnum_div(r1, r2));
}

// GC: may allocate via gc_alloc through vm_box_flonum.
#define DEFINE_VM_RUNTIME_DIVMOD_SLOW(name, fixnum_safe, fixnum_body,          \
                                      flonum_body, field)                      \
  gc_obj vm_runtime_math_##name##_slow(gc_obj v1, gc_obj v2) {                 \
    if (numeric_is_zero(v2)) {                                                 \
      abort();                                                                 \
    }                                                                          \
    if (is_flonum(v1) || is_flonum(v2)) {                                      \
      return vm_box_flonum((flonum_body));                                     \
    }                                                                          \
    if (is_fixnum(v1) && is_fixnum(v2) && (fixnum_safe)) {                     \
      return tag_fixnum((fixnum_body));                                        \
    }                                                                          \
    gc_add_root((const void *)&v2, 1, 0);                                      \
    gc_obj b1 = numeric_to_bignum_obj(v1);                                     \
    gc_add_root((const void *)&b1, 1, 0);                                      \
    gc_obj b2 = numeric_to_bignum_obj(v2);                                     \
    gc_add_root((const void *)&b2, 1, 0);                                      \
    bn_divmod_result_t qr = bn_divmod(to_bignum(b1), to_bignum(b2));           \
    gc_obj res = normalize_exact_integer(tag_bignum(qr.field));                \
    gc_remove_root((const void *)&b2, 0);                                      \
    gc_remove_root((const void *)&b1, 0);                                      \
    gc_remove_root((const void *)&v2, 0);                                      \
    return res;                                                                \
  }

DEFINE_VM_RUNTIME_DIVMOD_SLOW(quotient,
                              !fixnum_quotient_overflows(to_fixnum(v1),
                                                         to_fixnum(v2)),
                              to_fixnum(v1) / to_fixnum(v2),
                              trunc(numeric_to_double(v1) /
                                    numeric_to_double(v2)),
                              q)
DEFINE_VM_RUNTIME_DIVMOD_SLOW(mod, true, to_fixnum(v1) % to_fixnum(v2),
                              fmod(numeric_to_double(v1),
                                   numeric_to_double(v2)),
                              r)

#undef DEFINE_VM_RUNTIME_DIVMOD_SLOW

// GC: may allocate via gc_alloc through ratnum_cmp.
// NOLINTBEGIN(bugprone-macro-parentheses)
#define DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW(name, op)                           \
  gc_obj vm_runtime_cmp_##name##_slow(gc_obj v1, gc_obj v2) {                  \
    bool ordered;                                                              \
    int cmp = numeric_real_compare(v1, v2, &ordered);                          \
    return (ordered && (cmp op 0)) ? TRUE_REP : FALSE_REP;                     \
  }

DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW(lt, <)
DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW(gt, >)
DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW(lte, <=)
DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW(gte, >=)

#undef DEFINE_VM_RUNTIME_NUMERIC_CMP_SLOW
// NOLINTEND(bugprone-macro-parentheses)

gc_obj vm_runtime_cmp_jeqv_slow(gc_obj v1, gc_obj v2) {
  return obj_jeqv(v1, v2) ? TRUE_REP : FALSE_REP;
}

gc_obj vm_runtime_cmp_numeq_slow(gc_obj v1, gc_obj v2) {
  return numeric_eqv(v1, v2) ? TRUE_REP : FALSE_REP;
}

EXPORT gc_obj SCM_STR_COPY(gc_obj to, int start, gc_obj from, int fromstart,
                           int fromend) {
  auto tostr = to_string(to);
  auto fromstr = to_string(from);
  memcpy(&tostr->str[start], &fromstr->str[fromstart], fromend - fromstart);
  return to;
}

EXPORT uint64_t SCM_HASH_OBJ(gc_obj obj) { return hashmix(obj.value); }
EXPORT uint64_t SCM_STRING_HASH(const char *s, int32_t bound) {
  uint64_t hash = 5381;
  int c;
  while ((c = *s++))
    hash = ((hash << 5) + hash) + (unsigned char)c;
  return hash % (uint64_t)bound;
}
EXPORT bool SCM_ISNAN(double d) { return isnan(d); }
EXPORT bool SCM_ISINF(double d) { return isinf(d); }
EXPORT gc_obj SCM_GET_ENV_VARS() {
  gc_obj tail = NIL;
  gc_add_root((const void *)&tail, 1, 0);

#ifdef __APPLE__
  char **p = *_NSGetEnviron();
#else
  char **p = environ;
#endif
  while (*p) {
    char *split = strchr(*p, '=');
    if (split) {
      int64_t len = split - *p;
      size_t bytes = (sizeof(string_s) + len + 1 + 7) & ~(size_t)7;
      string_s *s = gc_alloc((uint64_t)bytes);
      s->header.type = STRING_TAG;
      s->len = tag_fixnum(len);
      memcpy(s->str, *p, len);
      s->str[len] = '\0';
      gc_obj var = tag_string(s);

      gc_obj val = make_string(split + 1);
      gc_obj pair = make_cons(var, val);
      tail = make_cons(pair, tail);
      p++;
    }
  }

  gc_remove_root((const void *)&tail, 0);
  return tail;
}
