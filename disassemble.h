#pragma once

#include <stddef.h>
#include <stdint.h>

#include "comments.h"

void disassemble(const uint8_t *code, size_t len,
                 const comment_entry *comments);
