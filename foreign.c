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

typedef union foreign_tmp {
  uint8_t u8;
  int32_t i32;
  int64_t i64;
  uint64_t u64;
  double f64;
  void *ptr;
} foreign_tmp;

static gc_obj foreign_owned_string(char *raw) {
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
  auto name = foreign_type_name(type_obj);
  if (strcmp(name, "uint8") == 0) {
    if (tmp && !is_fixnum(value)) {
      abort();
    }
    if (tmp) {
      tmp->u8 = (uint8_t)to_fixnum(value);
    }
    return &ffi_type_uint8;
  }
  if (strcmp(name, "int32") == 0) {
    if (tmp && !is_fixnum(value)) {
      abort();
    }
    if (tmp) {
      tmp->i32 = (int32_t)to_fixnum(value);
    }
    return &ffi_type_sint32;
  }
  if (strcmp(name, "int64") == 0) {
    if (tmp && !is_fixnum(value)) {
      abort();
    }
    if (tmp) {
      tmp->i64 = to_fixnum(value);
    }
    return &ffi_type_sint64;
  }
  if (strcmp(name, "uint64") == 0) {
    if (tmp && !is_fixnum(value)) {
      abort();
    }
    if (tmp) {
      tmp->u64 = (uint64_t)to_fixnum(value);
    }
    return &ffi_type_uint64;
  }
  if (strcmp(name, "double") == 0) {
    if (tmp && !is_fixnum(value) && !is_flonum(value)) {
      abort();
    }
    if (tmp) {
      tmp->f64 = numeric_to_double(value);
    }
    return &ffi_type_double;
  }
  if (strcmp(name, "string") == 0) {
    if (tmp && !is_string(value)) {
      abort();
    }
    if (tmp) {
      tmp->ptr = to_string(value)->str;
    }
    return &ffi_type_pointer;
  }
  abort();
}

static gc_obj foreign_return_value(gc_obj type_obj, foreign_tmp raw) {
  auto name = foreign_type_name(type_obj);
  if (strcmp(name, "uint8") == 0) {
    return tag_fixnum(raw.u8);
  }
  if (strcmp(name, "int32") == 0) {
    return tag_fixnum(raw.i32);
  }
  if (strcmp(name, "int64") == 0) {
    return tag_fixnum(raw.i64);
  }
  if (strcmp(name, "uint64") == 0) {
    return tag_fixnum((int64_t)raw.u64);
  }
  if (strcmp(name, "double") == 0) {
    return vm_box_flonum(raw.f64);
  }
  if (strcmp(name, "string") == 0) {
    return foreign_owned_string(raw.ptr);
  }
  abort();
}

gc_obj do_foreign_call(gc_obj sym_obj, gc_obj sig_obj, gc_obj const *args,
                       uint8_t argcnt) {
  if (!is_string(sym_obj) || !is_cons(sig_obj)) {
    abort();
  }

  auto sig = to_cons(sig_obj);
  gc_obj ret_type = sig->a;
  gc_obj sig_tail = sig->b;
  if (!is_cons(sig_tail)) {
    abort();
  }
  auto arg_types_list = to_cons(sig_tail)->a;

  ffi_cif cif;
  ffi_type *arg_types[UINT8_MAX] = {0};
  void *arg_values[UINT8_MAX] = {0};
  foreign_tmp arg_tmps[UINT8_MAX] = {0};
  ffi_type *ret_ffi_type = foreign_prep_type(ret_type, UNDEFINED, nullptr);
  foreign_tmp ret_tmp = {0};

  for (uint8_t i = 0; i < argcnt; i++) {
    if (!is_cons(arg_types_list)) {
      abort();
    }
    auto entry = to_cons(arg_types_list);
    arg_types[i] = foreign_prep_type(entry->a, args[i], &arg_tmps[i]);
    arg_values[i] = &arg_tmps[i];
    arg_types_list = entry->b;
  }
  if (arg_types_list.value != NIL_TAG) {
    abort();
  }

  static void *foreign_handle;
  if (!foreign_handle) {
    foreign_handle = dlopen(nullptr, RTLD_LAZY);
    if (!foreign_handle) {
      abort();
    }
  }

  auto sym = dlsym(foreign_handle, to_string(sym_obj)->str);
  if (!sym) {
    printf("Can't find foreign symbol: %s\n", to_string(sym_obj)->str);
    abort();
  }

  if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, argcnt, ret_ffi_type, arg_types) !=
      FFI_OK) {
    abort();
  }
  ffi_call(&cif, FFI_FN(sym), &ret_tmp, arg_values);
  return foreign_return_value(ret_type, ret_tmp);
}
