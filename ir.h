#pragma once

#include "stdint.h"

typedef struct {
  bool constant;
  uint16_t loc : 15;
} slot;
