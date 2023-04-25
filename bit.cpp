#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

enum {
  RET=0,
  KSHORT,
  ISGE,
  JMP,
  RET1,
  SUBVN,
  CALL,
  ADDVV,
};

struct ins{
  unsigned char code;
  unsigned char a;
  unsigned char b;
  unsigned char c;
};
/*
 (if (< n 2)
     n
     (+ (recursive (- n 1))
        (recursive (- n 2))))
 */
ins code[] = {
  {KSHORT, 1, 2},
  {ISGE, 0, 1},
  {JMP, 1, 4},
  {RET1, 0, 1},
  {SUBVN, 3, 0, 1},
  {CALL, 0, 1, 1},
  {SUBVN, 4, 0, 2},
  {CALL, 0, 2, 1},
  {ADDVV, 0, 1, 2},
  {RET1, 0, 1}
};

int main() {
  long*  stack = (long*)malloc(sizeof(long)*10000);
  stack[0] = -1;
  stack[1] = -1;
  stack[2] = 40; // VALUE
  long* frame = &stack[2];

  long pc = 0;

  while (pc >= 0) {
    ins i = code[pc];
    // printf("Running PC %li code %i\n", pc, i.code);
    // printf("%li %li \n", frame[0], frame[3]);

    switch (i.code) {
    case 1: {
      //      printf("KSHORT\n");
      frame[i.a] = i.b;
      pc++;
      break;
    }
    case 2: {
      //printf("ISGE\n");
      if (frame[0] >= frame[1]) {
	pc+=1;
      } else {
	pc+=2;
      }
      break;
    }
    case 3: {
      //printf("JMP\n");
      pc = i.b;
      break;
    }
    case 4: {
      //printf("RET\n");
      pc = frame[-2];
      frame[-2] = frame[i.a];
      frame -= frame[-1];
      //printf("Frame is %x\n", frame);
      break;
    }
    case 5: {
      //printf("SUBVN\n");
      frame[i.a] = frame[i.b] - i.c;
      pc++;
      break;
    }
    case 6: {
      // printf("CALL\n");
      // printf("Frame is %x\n", frame);
      frame[i.b] = pc + 1;
      frame[i.b+1] = i.b + 2;
      pc = i.a;
      frame += i.b + 2;
      // printf("Frame is %x\n", frame);
      break;
    }
    case 7: {
      //printf("ADDVV");
      frame[i.a] = frame[i.b] + frame[i.c];
      pc++;
      break;
    }
    default: {
      printf("Unknown i %i", i.code);
      exit(-1);
    }
    }

    //assert(pc < 10);
  }

  printf("Result:%li\n", stack[0]);
  
  return 0;
}
