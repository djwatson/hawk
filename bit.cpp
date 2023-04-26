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
  ALLOC,
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

/*
#define PARAMS unsigned char ra, unsigned instr,unsigned* pc, long* frame
#define ARGS ra, instr, pc, frame
#define MUSTTAIL __attribute__((musttail))
#define NEXT_INSTR { instr = *pc;		\
  unsigned char op = instr & 0xff;		\
  ra = (instr >> 8) & 0xff;			\
  instr >>= 16;					\
  MUSTTAIL return op_table[op](ARGS);		\
}
  


typedef void (*op_func)(PARAMS);

//#define DEBUG(name) printf("%s %li %li %li %li\n", name, frame[0], frame[1], frame[2], frame[3]);
#define DEBUG(name)

static op_func op_table[10];
void INS_KSHORT(PARAMS) {
  DEBUG("KSHORT");
  unsigned char rb = instr;
  
  frame[ra] = rb;
  
  pc++;
  NEXT_INSTR;
}

void INS_ISGE(PARAMS) {
  DEBUG("ISGE");
  unsigned char rb = instr;
  
  if (frame[ra] >= frame[rb]) {
    pc+=1;
  } else {
    pc+=2;
  }
  
  NEXT_INSTR;
}

void INS_JMP(PARAMS) {
  DEBUG("JMP");
  unsigned char rb = instr;
  
  pc += rb;
  
  NEXT_INSTR;
}

void INS_RET1(PARAMS) {
  DEBUG("RET1");
  
  pc = (unsigned int*)frame[-2];
  frame[-2] = frame[ra];
  frame -= frame[-1];
  
  NEXT_INSTR;
}

void INS_SUBVN(PARAMS) {
  DEBUG("SUBVN");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;
  
  frame[ra] = frame[rb] - rc;
  
  pc++;
  NEXT_INSTR;
}

void INS_CALL(PARAMS) {
  DEBUG("CALL");
  unsigned char rb = instr;
  
  frame[rb] = (long)(pc + 1);
  frame[rb+1] = rb + 2;
  pc = code;
  frame += rb + 2;
  
  NEXT_INSTR;
}

void INS_ADDVV(PARAMS) {
  DEBUG("ADDVV");
  unsigned char rb = instr & 0xff;
  unsigned char rc = (instr >> 8) & 0xff;
  
  frame[ra] = frame[rb] + frame[rc];
  
  pc++;
  NEXT_INSTR;
}

void INS_HALT(PARAMS) {
  DEBUG("HALT");
  printf("Result:%li\n", frame[ra]);
  exit(0);
}

void INS_UNKNOWN(PARAMS) {
  unsigned int c = *pc;
  printf("UNKNOWN INSTRUCTION %i\n", INS_OP(c));
  exit(-1);
}

*/
int main() {
  /*
  op_table[1] = INS_KSHORT;
  op_table[2] = INS_ISGE;
  op_table[3] = INS_JMP;
  op_table[4] = INS_RET1;
  op_table[5] = INS_SUBVN;
  op_table[6] = INS_CALL;
  op_table[7] = INS_ADDVV;
  op_table[8] = INS_HALT;
  */
  long*  stack = (long*)malloc(sizeof(long)*10000);
  stack[0] = (unsigned long)&code[10]; // return pc
  stack[1] = 2; // frame size
  stack[2] = 40; // VALUE
  long* frame = &stack[2];

  unsigned int* pc = &code[0];

  //////////NEW:
  // if(0) {
  // unsigned int instr = *pc;
  // unsigned char op = instr & 0xff;
  // unsigned char ra = (instr >> 8) & 0xff;
  // instr >>= 16;
  // op_table[op](ARGS);
  // }

  //////////////// OLD:

  void* l_op_table[] = {NULL,
    &&L_INS_KSHORT,
    &&L_INS_ISGE,
    &&L_INS_JMP,
    &&L_INS_RET1,
    &&L_INS_SUBVN,
    &&L_INS_CALL,
    &&L_INS_ADDVV,
    &&L_INS_HALT,
  };

  //#define DIRECT {i = *pc; goto *l_op_table[INS_OP(i)];}
#define DIRECT
  while (true) {
    unsigned int i = *pc;
    // printf("Running PC %li code %i %i %i %i %x\n", pc - code, INS_OP(i), INS_A(i), INS_B(i), INS_C(i), i);
    // printf("%li %li \n", frame[0], frame[3]);
    
    goto *l_op_table[INS_OP(i)];
      
    switch (INS_OP(i)) {
    case 1: {
      L_INS_KSHORT:
      //      printf("KSHORT\n");
      frame[INS_A(i)] = INS_B(i);
      pc++;
      DIRECT;
      break;
    }
    case 2: {
      L_INS_ISGE:
      //printf("ISGE\n");
      if (frame[0] >= frame[1]) {
	pc+=1;
      } else {
	pc+=2;
      }
      DIRECT;
      break;
    }
    case 3: {
      L_INS_JMP:
      //printf("JMP\n");
      pc += INS_B(i);
      DIRECT;
      break;
    }
    case 4: {
      L_INS_RET1:
      //printf("RET\n");
      pc = (unsigned int*)frame[-2];
      frame[-2] = frame[INS_A(i)];
      frame -= frame[-1];
      //printf("Frame is %x\n", frame);
      DIRECT;
      break;
    }
    case 5: {
      L_INS_SUBVN:
      //printf("SUBVN\n");
      frame[INS_A(i)] = frame[INS_B(i)] - INS_C(i);
      pc++;
      DIRECT;
      break;
    }
    case 6: {
      L_INS_CALL:
      // printf("CALL\n");
      // printf("Frame is %x\n", frame);
      frame[INS_B(i)] = (long)(pc + 1);
      frame[INS_B(i)+1] = INS_B(i) + 2;
      pc = code;
      frame += INS_B(i) + 2;
      // printf("Frame is %x\n", frame);
      DIRECT;
      break;
    }
    case 7: {
      L_INS_ADDVV:
      //printf("ADDVV");
      frame[INS_A(i)] = frame[INS_B(i)] + frame[INS_C(i)];
      pc++;
      DIRECT;
      break;
    }
    case 8: {
      L_INS_HALT:
      printf("Result:%li\n", frame[INS_A(i)]);
      exit(0);
      break;
    }
    case 9: {
      frame[INS_A(i)] = (long)malloc(INS_B(i));
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
