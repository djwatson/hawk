#pragma once

#include "ir.h"

typedef enum : uint8_t {
  LOC_REG,
  LOC_SPILL,
} loc_kind;

typedef struct {
  loc_kind kind;
  uint8_t reg;
  uint8_t spill;
  uint16_t value_id; // TODO could remove?
} dense_loc_entry;

typedef enum : uint8_t {
  REGISTER_OP_RELOAD,
  REGISTER_OP_MOVE,
} register_op_kind;

typedef struct {
  uint16_t ir_idx;
  bool before;
  register_op_kind kind;
  uint16_t value_id;
  uint8_t reg;
  uint8_t src_reg;
  uint8_t spill;
} register_op;

typedef struct regalloc2_result {
  dense_loc_entry *dense_locs;
  uint16_t *ir_id_to_dense_map;
  register_op *register_ops;
} regalloc2_result;

regalloc2_result regalloc2(trace *t);
void regalloc2_result_free(regalloc2_result *r);
