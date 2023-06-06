#include <stdlib.h>
#include <stdio.h>
unsigned long stuff[] = {0, 1, 2, 3, 4};

static void toggle_ac_flag() {
  asm inline (
	       "pushfq\n"
	       "btcq $18, (%%rsp)\n"
       "popfq\n":  : : "cc");
}

int main(int argc, char* argv[]) {
  int offset = atoi(argv[1]);
  printf("Using offset %i\n", offset);
  long flags = 0;;
  unsigned long* foo = (unsigned long*)((long)stuff +offset);
  toggle_ac_flag();
  unsigned long val = *foo;
  toggle_ac_flag();
  printf("%li\n", val);
  return 0;
}
