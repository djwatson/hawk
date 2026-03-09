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

typedef struct {
  uint16_t ir_idx;
  uint16_t value_id;
  uint8_t reg;
} reload_op;

typedef struct regalloc_result {
  dense_loc_entry *dense_locs;
  uint16_t *ir_id_to_dense_map;
  reload_op *reload_ops;
} regalloc_result;

regalloc_result regalloc(trace *t);
void regalloc_result_free(regalloc_result *r);
