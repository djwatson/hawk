#pragma once

void record_start(unsigned int *pc, long *frame);
int record_instr(unsigned int *pc, long *frame);
unsigned int* record_run(unsigned int trace, long *frame);
