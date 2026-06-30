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
  return name->str;
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
  gc_obj arg_types_list = name_and_args->b;
  if (!is_string(sym_obj) || !is_cons(arg_types_list)) {
    abort();
  }
  sig->name = to_string(sym_obj)->str;
  sig->sym = foreign_dlsym(sig->name);
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
  size_t len = strlen(raw);
  size_t bytes = (sizeof(string_s) + len + 1 + 7) & ~(size_t)7;
  string_s *str = gc_alloc((uint64_t)bytes);
  str->header.type = STRING_TAG;
  str->len = tag_fixnum((int64_t)len);
  memcpy(str->str, raw, len + 1);
  free(raw);
  return tag_string(str);
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
    /* This raw char* is not GC-stable if the foreign callee can reenter
     * Scheme or otherwise trigger collection. */
    tmp->ptr = to_string(value)->str;
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
  gc_remove_root((const void *)&sig_obj, 0);
  return out;
}
