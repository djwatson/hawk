// Copyright 2024 Dave Watson <dade.watson@gmail.com>
#define _DEFAULT_SOURCE

#include <dlfcn.h>
#include <ffi.h>
#include <stdint.h>
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

static ffi_type *foreign_prep_type(gc_obj type_obj, gc_obj value,
                                   foreign_tmp *tmp) {
  switch (foreign_parse_type(type_obj)) {
  case FOREIGN_TYPE_UINT8:
    if (tmp && !is_fixnum(value)) {
      abort();
    }
    if (tmp) {
      tmp->u8 = (uint8_t)to_fixnum(value);
    }
    return &ffi_type_uint8;
  case FOREIGN_TYPE_INT32:
    if (tmp && !is_fixnum(value)) {
      abort();
    }
    if (tmp) {
      tmp->i32 = (int32_t)to_fixnum(value);
    }
    return &ffi_type_sint32;
  case FOREIGN_TYPE_INT64:
    if (tmp && !is_fixnum(value)) {
      abort();
    }
    if (tmp) {
      tmp->i64 = to_fixnum(value);
    }
    return &ffi_type_sint64;
  case FOREIGN_TYPE_UINT64:
    if (tmp && !is_fixnum(value)) {
      abort();
    }
    if (tmp) {
      tmp->u64 = (uint64_t)to_fixnum(value);
    }
    return &ffi_type_uint64;
  case FOREIGN_TYPE_DOUBLE:
    if (tmp && !is_fixnum(value) && !is_flonum(value)) {
      abort();
    }
    if (tmp) {
      tmp->f64 = numeric_to_double(value);
    }
    return &ffi_type_double;
  case FOREIGN_TYPE_STRING:
    if (tmp && !is_string(value)) {
      abort();
    }
    if (tmp) {
      tmp->ptr = to_string(value)->str;
    }
    return &ffi_type_pointer;
  case FOREIGN_TYPE_GC_OBJ:
    if (tmp) {
      tmp->u64 = (uint64_t)value.value;
    }
    return &ffi_type_uint64;
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
  default:
    abort();
  }
}

gc_obj do_foreign_call(gc_obj sig_obj, gc_obj const *args, uint8_t argcnt) {
  foreign_sig sig;
  foreign_parse_sig(sig_obj, &sig);
  if (sig.argcnt != argcnt) {
    abort();
  }

  ffi_cif cif;
  ffi_type *arg_types[UINT8_MAX] = {0};
  void *arg_values[UINT8_MAX] = {0};
  foreign_tmp arg_tmps[UINT8_MAX] = {0};
  gc_obj ret_type = to_cons(sig_obj)->a;
  ffi_type *ret_ffi_type = foreign_prep_type(ret_type, UNDEFINED, nullptr);
  foreign_tmp ret_tmp = {0};

  gc_obj arg_types_list = to_cons(to_cons(to_cons(sig_obj)->b)->b)->a;
  for (uint8_t i = 0; i < sig.argcnt; i++) {
    auto entry = to_cons(arg_types_list);
    arg_types[i] = foreign_prep_type(entry->a, args[i], &arg_tmps[i]);
    arg_values[i] = &arg_tmps[i];
    arg_types_list = entry->b;
  }

  if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, sig.argcnt, ret_ffi_type,
                   arg_types) !=
      FFI_OK) {
    abort();
  }
  ffi_call(&cif, FFI_FN(sig.sym), &ret_tmp, arg_values);
  return foreign_return_value(ret_type, ret_tmp);
}
