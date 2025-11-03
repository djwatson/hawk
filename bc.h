#pragma once

#include <stdint.h>

#define OPS					\
  X(ADD)					\
    X(SUB)					\
    X(KSHORT)					\
    X(CONST)					\
    X(RET)					\
    X(LOOKUP)					\
    X(FUNC)					\
    X(LT)					\
    X(IF)					\
    X(CLOSURE_GET)					\
    X(LCALL)					\
    X(HALT)					
typedef enum : uint8_t {
#define X(name) OP_##name,
  OPS
  #undef X
    OP_INS_MAX,
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
