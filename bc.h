#pragma once

#include <stdint.h>

typedef enum : uint8_t {
  OP_ADD,
  OP_SUB,
  OP_CONST,
  OP_RET,
  OP_LOOKUP,
  OP_FUNC,
  OP_LT,
  OP_IF,
  OP_CLOSURE_GET,
  OP_LCALL,
  OP_HALT,
} ops;

typedef struct bc {
  union {
    struct {
      ops op;
      uint8_t reg;
      union {
        struct {
          uint8_t v1;
          uint8_t v2;
        };
        uint16_t data;
      };
    };
    uint32_t full_data;
  };
} bc;

static_assert(sizeof(bc) == 4, "bc instructions must be 4 bytes");
