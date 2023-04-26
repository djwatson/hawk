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
  HALT,
};

/*
 (if (< n 2)
     n
     (+ (recursive (- n 1))
        (recursive (- n 2))))
 */
#define CODE(i,a,b,c) ((c << 24) | (b << 16) | (a << 8) | i)
#define INS_OP(i) (i&0xff)
#define INS_A(i) ((i>>8)&0xff)
#define INS_B(i) ((i>>16)&0xff)
#define INS_C(i) ((i>>24)&0xff)

unsigned int code[] = {
  CODE(KSHORT, 1, 2, 0),
    CODE(ISGE, 0, 1, 0),
    CODE(JMP, 1, 2, 0),
    CODE(RET1, 0, 1, 0),
    CODE(SUBVN, 3, 0, 1),
    CODE(CALL, 0, 1, 1),
    CODE(SUBVN, 4, 0, 2),
    CODE(CALL, 0, 2, 1),
    CODE(ADDVV, 0, 1, 2),
    CODE(RET1, 0, 0, 0),
    CODE(HALT, 0, 0, 0)
    };


#define PARAMS unsigned char ra, void* table, unsigned instr,unsigned* pc, long* frame
#define ARGS ra, table, instr, pc, frame

#define MUSTTAIL __attribute__((musttail))

typedef void (*op_func)(PARAMS);

void INS_KSHORT(PARAMS) {
  op_func *op_table = (op_func*)table;
  unsigned char rb = instr & 0xff;
  
  frame[ra] = rb;
  
  pc++;
  instr = *pc;
  unsigned char op = instr & 0xff;
  ra = (instr >> 8) & 0xff;
  instr >>= 16;
  MUSTTAIL return op_table[op](ARGS);
}

op_func op_table[] = {NULL, INS_KSHORT/*, INS_ISGE, INS_JMP, INS_RET1, INS_SUBVN, INS_CALL, INS_ADDVV*/};

int main() {
  long*  stack = (long*)malloc(sizeof(long)*10000);
  stack[0] = (unsigned long)&code[10]; // return pc
  stack[1] = 2; // frame size
  stack[2] = 40; // VALUE
  long* frame = &stack[2];

  unsigned int* pc = &code[0];

  while (true) {
    unsigned int i = *pc;
    // printf("Running PC %li code %i %i %i %i %x\n", pc - code, INS_OP(i), INS_A(i), INS_B(i), INS_C(i), i);
    // printf("%li %li \n", frame[0], frame[3]);

    switch (INS_OP(i)) {
    case 1: {
      //      printf("KSHORT\n");
      frame[INS_A(i)] = INS_B(i);
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
      pc += INS_B(i);
      break;
    }
    case 4: {
      //printf("RET\n");
      pc = (unsigned int*)frame[-2];
      frame[-2] = frame[INS_A(i)];
      frame -= frame[-1];
      //printf("Frame is %x\n", frame);
      break;
    }
    case 5: {
      //printf("SUBVN\n");
      frame[INS_A(i)] = frame[INS_B(i)] - INS_C(i);
      pc++;
      break;
    }
    case 6: {
      // printf("CALL\n");
      // printf("Frame is %x\n", frame);
      frame[INS_B(i)] = (long)(pc + 1);
      frame[INS_B(i)+1] = INS_B(i) + 2;
      pc = code;
      frame += INS_B(i) + 2;
      // printf("Frame is %x\n", frame);
      break;
    }
    case 7: {
      //printf("ADDVV");
      frame[INS_A(i)] = frame[INS_B(i)] + frame[INS_C(i)];
      pc++;
      break;
    }
    case 8: {
      printf("Result:%li\n", frame[INS_A(i)]);
      exit(0);
      break;
    }
    default: {
      printf("Unknown i %i", INS_OP(i));
      exit(-1);
    }
    }

    //assert(pc < 10);
  }
  
  return 0;
}
