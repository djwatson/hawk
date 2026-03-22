#pragma once

#include <stdint.h>

#include "types.h"

gc_obj do_foreign_call(gc_obj sig_obj, gc_obj const *args, uint8_t argcnt);
