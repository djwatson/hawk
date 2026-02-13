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
  uint16_t value_id;
} dense_loc_entry;

typedef struct {
  bool present;
  dense_loc_entry loc;
} ir_output_loc;

typedef struct {
  uint16_t ir_idx;
  bool before;
  bool is_reload;
  uint16_t value_id;
  uint8_t reg;
  uint8_t spill;
} spill_reload_op;

typedef struct {
  dense_loc_entry *dense_locs;
  ir_output_loc *ir_output_locs;
  uint16_t *ir_id_to_dense_map;
  uint16_t *snap_id_to_dense_map;
  spill_reload_op *spill_reload_ops;
} regalloc2_result;

regalloc2_result regalloc2(trace *t);
void regalloc2_print(trace *t, regalloc2_result const *r);
void regalloc2_result_free(regalloc2_result *r);
