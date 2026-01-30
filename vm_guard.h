#pragma once

#include <assert.h>

#include "types.h"

static inline bool guard_obj_matches(gc_obj val, gc_obj want_tag_obj) {
  assert(is_fixnum(want_tag_obj));
  uint64_t want_tag = (uint64_t)to_fixnum(want_tag_obj);
  uint64_t got_tag = (uint64_t)get_type_tag(val);

  assert((want_tag & TAG_MASK) != PTR_TAG); // todo
  if (got_tag == LITERAL_TAG) {
    return (((uint64_t)val.value & IMMEDIATE_MASK) == want_tag);
  }
  return got_tag == want_tag;
}
