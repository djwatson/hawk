#pragma once

#include <stdint.h>

#include "types.h"

typedef enum : uint8_t {
  FOREIGN_TYPE_UINT8,
  FOREIGN_TYPE_INT32,
  FOREIGN_TYPE_INT64,
  FOREIGN_TYPE_UINT64,
  FOREIGN_TYPE_DOUBLE,
  FOREIGN_TYPE_STRING,
  FOREIGN_TYPE_GC_OBJ,
} foreign_type;

typedef struct {
  foreign_type ret_type;
  foreign_type arg_types[UINT8_MAX];
  uint8_t argcnt;
  const char *name;
  void *sym;
} foreign_sig;

foreign_type foreign_parse_type(gc_obj type_obj);
void foreign_parse_sig(gc_obj sig_obj, foreign_sig *sig);
gc_obj foreign_owned_string(char *raw);
gc_obj do_foreign_call(gc_obj sig_obj, gc_obj const *args, uint8_t argcnt);
