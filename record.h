#pragma once

int record(unsigned int *pc, long *frame);
int record_instr(unsigned int *pc, long *frame);
void record_run(unsigned int tnum, unsigned int** o_pc, long** o_frame, long* frame_top);
