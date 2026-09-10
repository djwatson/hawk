// Copyright 2024 Dave Watson <dade.watson@gmail.com>
#define _DEFAULT_SOURCE

#include <dlfcn.h>
#include <stdint.h>

#include "ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "foreign.h"
#include "runtime.h"

static const char *foreign_type_name(gc_obj type_obj) {
  if (!is_symbol(type_obj)) {
    abort();
  }
  auto name = get_sym_name(to_symbol(type_obj));
  if (!name) {
    abort();
  }
  return string_utf8(name);
}

static void *foreign_dlsym(const char *name) {
  static void *foreign_handle;
  if (!foreign_handle) {
    foreign_handle = dlopen(nullptr, RTLD_LAZY);
    if (!foreign_handle) {
      abort();
    }
  }

  auto sym = dlsym(foreign_handle, name);
  if (!sym) {
    printf("Can't find foreign symbol: %s\n", name);
    abort();
  }
  return sym;
}

foreign_type foreign_parse_type(gc_obj type_obj) {
  auto name = foreign_type_name(type_obj);
  if (strcmp(name, "uint8") == 0) {
    return FOREIGN_TYPE_UINT8;
  }
  if (strcmp(name, "int32") == 0) {
    return FOREIGN_TYPE_INT32;
  }
  if (strcmp(name, "int64") == 0) {
    return FOREIGN_TYPE_INT64;
  }
  if (strcmp(name, "uint64") == 0) {
    return FOREIGN_TYPE_UINT64;
  }
  if (strcmp(name, "double") == 0) {
    return FOREIGN_TYPE_DOUBLE;
  }
  if (strcmp(name, "string") == 0) {
    return FOREIGN_TYPE_STRING;
  }
  if (strcmp(name, "gc_obj") == 0) {
    return FOREIGN_TYPE_GC_OBJ;
  }
  if (strcmp(name, "bool") == 0) {
    return FOREIGN_TYPE_BOOL;
  }
  abort();
}

void foreign_parse_sig(gc_obj sig_obj, foreign_sig *sig) {
  if (!is_cons(sig_obj)) {
    abort();
  }

  memset(sig, 0, sizeof(*sig));

  auto sig_cons = to_cons(sig_obj);
  sig->ret_type = foreign_parse_type(sig_cons->a);
  auto sig_tail = sig_cons->b;
  if (!is_cons(sig_tail)) {
    abort();
  }
  auto name_and_args = to_cons(sig_tail);
  gc_obj sym_obj = name_and_args->a;
  foreign_strings_begin();
  gc_obj arg_types_list = name_and_args->b;
  if (!is_string(sym_obj) || !is_cons(arg_types_list)) {
    abort();
  }
  sig->name = sym_obj;
  sig->sym = foreign_dlsym(string_utf8(to_string(sym_obj)));
  arg_types_list = to_cons(arg_types_list)->a;

  while (arg_types_list.value != NIL_TAG) {
    if (sig->argcnt == UINT8_MAX || !is_cons(arg_types_list)) {
      abort();
    }
    auto entry = to_cons(arg_types_list);
    sig->arg_types[sig->argcnt++] = foreign_parse_type(entry->a);
    arg_types_list = entry->b;
  }
}

typedef union foreign_tmp {
  uint8_t u8;
  int32_t i32;
  int64_t i64;
  uint64_t u64;
  double f64;
  void *ptr;
} foreign_tmp;

gc_obj foreign_owned_string(char *raw) {
  if (!raw) {
    abort();
  }
  gc_obj str = make_string(raw);
  free(raw);
  return str;
}

static void foreign_fill_arg(foreign_type type, gc_obj value,
                             foreign_tmp *tmp) {
  switch (type) {
  case FOREIGN_TYPE_UINT8:
    if (!is_fixnum(value)) {
      abort();
    }
    tmp->u8 = (uint8_t)to_fixnum(value);
    return;
  case FOREIGN_TYPE_INT32:
    if (!is_fixnum(value)) {
      abort();
    }
    tmp->i32 = (int32_t)to_fixnum(value);
    return;
  case FOREIGN_TYPE_INT64:
    if (!is_fixnum(value)) {
      abort();
    }
    tmp->i64 = to_fixnum(value);
    return;
  case FOREIGN_TYPE_UINT64:
    if (!is_fixnum(value)) {
      abort();
    }
    tmp->u64 = (uint64_t)to_fixnum(value);
    return;
  case FOREIGN_TYPE_DOUBLE:
    if (!is_fixnum(value) && !is_flonum(value)) {
      abort();
    }
    tmp->f64 = numeric_to_double(value);
    return;
  case FOREIGN_TYPE_STRING:
    if (!is_string(value)) {
      abort();
    }
    tmp->ptr = foreign_string_arg(value);
    return;
  case FOREIGN_TYPE_GC_OBJ:
    tmp->u64 = (uint64_t)value.value;
    return;
  case FOREIGN_TYPE_BOOL:
    tmp->u8 = value.value == TRUE_REP.value ? 1 : 0;
    return;
  default:
    abort();
  }
}

static gc_obj foreign_return_value(gc_obj type_obj, foreign_tmp raw) {
  switch (foreign_parse_type(type_obj)) {
  case FOREIGN_TYPE_UINT8:
    return tag_fixnum(raw.u8);
  case FOREIGN_TYPE_INT32:
    return tag_fixnum(raw.i32);
  case FOREIGN_TYPE_INT64:
    return tag_fixnum(raw.i64);
  case FOREIGN_TYPE_UINT64:
    return tag_fixnum((int64_t)raw.u64);
  case FOREIGN_TYPE_DOUBLE:
    return vm_box_flonum(raw.f64);
  case FOREIGN_TYPE_STRING:
    return foreign_owned_string(raw.ptr);
  case FOREIGN_TYPE_GC_OBJ:
    return (gc_obj){.value = (int64_t)raw.u64};
  case FOREIGN_TYPE_BOOL:
    return raw.u8 ? TRUE_REP : FALSE_REP;
  default:
    abort();
  }
}

gc_obj do_foreign_call(gc_obj sig_obj, gc_obj const *args, uint8_t argcnt) {
  gc_add_root((const void *)&sig_obj, 1, 0);
  foreign_sig sig;
  foreign_parse_sig(sig_obj, &sig);
  if (sig.argcnt != argcnt) {
    printf("Invalid foreign call, bad argcnt\n");
    abort();
  }

  foreign_type arg_types[UINT8_MAX];
  void *arg_values[UINT8_MAX];
  foreign_tmp arg_tmps[UINT8_MAX] = {0};
  foreign_tmp ret_tmp = {0};

  foreign_strings_begin();
  gc_obj arg_types_list = to_cons(to_cons(to_cons(sig_obj)->b)->b)->a;
  for (uint8_t i = 0; i < sig.argcnt; i++) {
    auto entry = to_cons(arg_types_list);
    foreign_type t = foreign_parse_type(entry->a);
    foreign_fill_arg(t, args[i], &arg_tmps[i]);
    arg_types[i] = t;
    arg_values[i] = &arg_tmps[i];
    arg_types_list = entry->b;
  }

  ffi_call_foreign(sig.sym, &ret_tmp, sig.ret_type, arg_values, arg_types,
                   sig.argcnt);
  gc_obj out = foreign_return_value(to_cons(sig_obj)->a, ret_tmp);
  foreign_strings_end();
  gc_remove_root((const void *)&sig_obj, 0);
  return out;
}

// Each call owns its UTF-8 arguments, including across nested foreign calls.
typedef struct foreign_strings {
  struct foreign_strings *parent;
  char *args[UINT8_MAX];
  unsigned count;
} foreign_strings;
static _Thread_local foreign_strings *string_args;

void foreign_strings_begin(void) {
  foreign_strings *frame = calloc(1, sizeof(*frame));
  if (!frame)
    abort();
  frame->parent = string_args;
  string_args = frame;
}

char *foreign_string_arg(gc_obj value) {
  char *raw = string_to_utf8(to_string(value));
  string_args->args[string_args->count++] = raw;
  return raw;
}

void foreign_strings_end(void) {
  foreign_strings *frame = string_args;
  for (unsigned i = 0; i < frame->count; i++)
    free(frame->args[i]);
  string_args = frame->parent;
  free(frame);
}
