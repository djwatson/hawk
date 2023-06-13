#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

static uint8_t *mtop = NULL;
static uint8_t *mend = NULL;
static uint8_t *p = NULL;

static const size_t page_cnt = 1000;
static const size_t msize = page_cnt * 4096;

#define auto __auto_type

enum registers {
  RAX = 0,
  RCX = 1,
  RDX = 2,
  RBX = 3,
  RSP = 4,
  RDP = 5,
  RSI = 6,
  RDI = 7,
  R8 = 8,
  R9 = 9,
  R10 = 10,
  R11 = 11,
  R12 = 12,
  R13 = 13,
  R14 = 14,
  R15 = 15,
};

/////////////////// instruction encoding

void emit_rex(uint8_t w, uint8_t r, uint8_t x, uint8_t b) {
  *(--p) = 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
}

void emit_modrm(uint8_t mod, uint8_t reg, uint8_t rm) {
  *(--p) = (mod << 6) | (reg << 3) | rm;
}

void emit_sib(uint8_t scale, uint8_t index, uint8_t base) {
  *(--p) = (scale << 6) | ((0x7 & index) << 3) | ((0x7 & base));
}

void emit_imm64(int64_t imm) {
  p -= sizeof(int64_t);
  *(int64_t *)p = imm;
}

void emit_imm32(int32_t imm) {
  p -= sizeof(int32_t);
  *(int32_t *)p = imm;
}

void emit_mov64(uint8_t r, int64_t imm) {
  emit_imm64(imm);
  *(--p) = 0xb8 | (0x7 & r);
  emit_rex(1, 0, 0, r >> 3);
}

void emit_call_indirect(uint8_t r) {
  emit_modrm(0x3, 0x2, 0x7 & r);
  *(--p) = 0xff;
  emit_rex(1, 0, 0, r >> 3);
}

// TODO offset
void emit_call32(int32_t offset) {
  emit_imm32(offset);
  *(--p) = 0xe8;
}

void emit_ret() { *(--p) = 0xc3; }

void emit_cmp_reg_imm32(uint8_t r, int32_t imm) {
  emit_imm32(imm);
  emit_modrm(0x3, 0x7, 0x7 & r);
  *(--p) = 0x81;
  emit_rex(1, 0, 0, r >> 3);
}

void emit_cmp_reg_reg(uint8_t src, uint8_t dst) {
  emit_modrm(0x3, 0x7 & src, 0x7 & dst);
  *(--p) = 0x3b;
  emit_rex(1, src >> 3, 0, dst >> 3);
}

enum jcc_cond {
  JA = 0x87,
  JAE = 0x83,
  JB = 0x82,
  JBE = 0x84,
  JC = 0x82,
  JE = 0x84,
  JZ = 0x84,
  JG = 0x8f,
  JGE = 0x8d,
  JL = 0x8c,
  JLE = 0x8e,
  JNA = 0x86,
  JNAE = 0x82,
  JNB = 0x83,
  JBC = 0x83,
  JNC = 0x83,
  JNE = 0x85,
  JNG = 0x8e,
  JNGE = 0x8c,
  JNL = 0x8b,
  JNLE = 0x8f,
  JNO = 0x81,
  JNP = 0x8b,
  JNS = 0x89,
  JNZ = 0x85,
  JO = 0x80,
  JP = 0x8a,
  JPE = 0x8a,
  JPO = 0x8b,
  JS = 0x88,
};

// TODO: could test for short offset
void emit_jcc32(enum jcc_cond cond, int32_t offset) {
  emit_imm32(offset);
  *(--p) = cond;
  *(--p) = 0x0f;
}

void emit_jmp32(int32_t offset) {
  emit_imm32(offset);
  *(--p) = 0xe9;
}

void emit_reg_reg(uint8_t opcode, uint8_t src, uint8_t dst) {
  emit_modrm(0x3, 0x7 & src, 0x7 & dst);
  *(--p) = opcode;
  emit_rex(1, src >> 3, 0, dst >> 3);
}

void emit_mem_reg_sib(uint8_t opcode, int32_t offset, uint8_t scale,
                      uint8_t index, uint8_t base, uint8_t reg) {
  emit_imm32(offset);
  emit_sib(scale, index, base);
  emit_modrm(0x2, 0x7 & reg, 0x4);
  *(--p) = opcode;
  emit_rex(1, reg >> 3, index >> 3, base >> 3);
}

void emit_mem_reg(uint8_t opcode, int32_t offset, uint8_t r1, uint8_t r2) {
  if ((0x7 & r1) == RSP) {
    emit_mem_reg_sib(opcode, offset, 0, r1, r1, r2);
  } else {
    emit_imm32(offset);
    emit_modrm(0x2, 0x7 & r2, 0x7 & r1);
    *(--p) = opcode;
    emit_rex(1, r2 >> 3, 0, r1 >> 3);
  }
}

/////////////////// opcodes

enum OPCODES {
  OP_ADD = 0x01,
  OP_XCHG = 0x87,
  OP_MOV = 0x89,
  OP_MOV_MR = 0x8b,
  OP_MOV_RM = 0x89,
  OP_NOP = 0x90,
  OP_XOR = 0x90,
  OP_TEST = 0x85,
  OP_LEA = 0x8d,
};

// TODO: could test for smaller immediates.
void emit_add_imm32(uint8_t src, int32_t imm) {
  emit_imm32(imm);
  emit_reg_reg(0x81, 0, src);
}

void emit_sub_imm32(uint8_t src, int32_t imm) {
  emit_imm32(imm);
  emit_reg_reg(0x81, 5, src);
}

// TODO: these could be short form.
void emit_push(uint8_t r) {
  emit_modrm(0x3, 6, 0x7 & r);
  *(--p) = 0xff;
  emit_rex(1, 0, 0, r >> 3);
}

void emit_pop(uint8_t r) {
  emit_modrm(0x3, 0, 0x7 & r);
  *(--p) = 0x8f;
  emit_rex(1, 0, 0, r >> 3);
}

void emit_cmovl(uint8_t dst, uint8_t src) {
  emit_modrm(0x3, 0x7 & src, 0x7 & dst);
  *(--p) = 0x4c;
  *(--p) = 0x0f;
  emit_rex(1, src >> 3, 0, dst >> 3);
}

/////////////////// memory

void* emit_offset() {
  return (void*)p;
}

void emit_check() {
  if (p - mtop <= 64) {
    printf("Fail: Out of jit memory\n");
    exit(-1);
  }
}

void emit_init() {
  if (mtop) {
    return;
  }
  
  mtop = (uint8_t *)mmap(NULL, msize, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  assert(mtop);
  p = mtop + msize;
  mend = p;
}

void emit_cleanup() { munmap(mtop, msize); }

/*
int main() {
  emit_init();
  auto end = emit_offset();
  emit_check();

  emit_ret();
  //emit_mov64(RAX, 101);

  //emit_imm32(101);
  // *(--p) = 0xb8 | RAX;

  long foo = 101;
  emit_imm64((int64_t)&foo);
  *(--p) = 0xa1;
  emit_rex(1, 0, 0, 0);

  //disassemble(emit_offset(), end - emit_offset());

  long (*res)(void) = emit_offset();

  long result = res();
  printf("Res: %li\n", result);
  
  emit_cleanup();
  
  return 0;
}
*/
