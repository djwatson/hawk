unsigned int* pc_start;
unsigned int instr_count;

void record_start(unsigned int* pc) {
  pc_start = pc;
  instr_count = 0;
}

void record_instr(unsigned int* pc) {
}
