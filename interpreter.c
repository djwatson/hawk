#include "luajit/dynasm/dasm_proto.h"
#include "luajit/dynasm/dasm_x86.h"
#include "bc.h"
#include "hawk.h"
#include "types.h"

#include <stddef.h>
#include <stdio.h>
#include <capstone/capstone.h> // for cs_insn, cs_close, cs_disasm, cs_free

extern uint8_t hotmap[];
extern uint8_t max_trace;

#define HOTMAP_MASK 0x3f
#define HOTMAP_CNT 200
#define BC_CONST_CNT_OFF offsetof(bcfunc, const_cnt)
#define BC_DATA_OFF offsetof(bcfunc, data)
#define SYMBOL_VAL_OFF offsetof(symbol, val)
#define CLOSURE_V_OFF offsetof(closure_s, v)

static void disassemble(const uint8_t *code, int len) {
  csh handle;
  cs_insn *insn;
  size_t count;

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    return;
  }
  cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL); // Set Intel syntax
  count = cs_disasm(handle, code, len, (uint64_t)code, 0, &insn);
  if (count > 0) {
    size_t j;
    for (j = 0; j < count; j++) {
      printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
             insn[j].op_str);
    }

    cs_free(insn, count);
  } else {
    printf("ERROR: Failed to disassemble given code!\n");
  }

  cs_close(&handle);
}

|.arch x64
|.section code_op, code_sub

|.actionlist build_actionlist
|.globals lbl_
|.globalnames globnames
|.externnames extnames

|.define STACK,		rsi
|.define PC,		rdi
|.define DISPATCH,	rdx
|.define FIXNUM_MASK,	-8

enum {
#define X(name) pc_##name,
  OPS
#undef X
  pc__MAX
};

|.macro dispatch_next
|  movzx eax, byte [PC+4]
|  add PC, 4
|  mov rax, qword [DISPATCH+rax*8]
|  jmp rax
|.endmacro

   #if _WIN32
#include <Windows.h>
#else
#include <sys/mman.h>
#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

static void* buf;
static size_t link_and_encode(dasm_State** d)
{
  size_t sz;
  dasm_link(d, &sz);
  buf = mmap(nullptr, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  dasm_encode(d, buf);
  mprotect(buf, sz, PROT_READ | PROT_EXEC);
  return sz;
}

typedef gc_obj PRESERVE_NONE (*op_func)(bc *pc, gc_obj *stack, void* op_table, uint8_t argcnt);
extern op_func impls[OP_INS_MAX];

void build_interpreter() {
  dasm_State* d;
  dasm_State** Dst = &d;
  unsigned npc = OP_INS_MAX;
  dasm_init(Dst, DASM_MAXSECTION);
  void* labels[lbl__MAX];

  dasm_setupglobal(Dst, labels, lbl__MAX);
  dasm_setup(Dst, build_actionlist);
  dasm_growpc(Dst, npc);
  
  |->op_sub:
  |  mov ax, [PC+2]
  |  movzx ecx, ah
  |  movzx eax, al
  |  mov rax, qword [STACK+rax*8]
  |  sub rax, qword [STACK+rcx*8]
  |  movzx ecx, byte [PC+1]
  |  mov qword [STACK+rcx*8], rax
  |  dispatch_next
  |->op_add:
  |  mov ax, [PC+2]
  |  movzx ecx, ah
  |  movzx eax, al
  |  mov rax, qword [STACK+rax*8]
  |  add rax, qword [STACK+rcx*8]
  |  movzx ecx, byte [PC+1]
  |  mov qword [STACK+rcx*8], rax
  |  dispatch_next
  |->op_const:
  |  movzx eax, word [PC+2]
  |  shl eax, 2
  |  mov rcx, PC
  |  sub rcx, rax
  |  mov rax, qword [rcx]
  |  movzx ecx, byte [PC+1]
  |  mov qword [STACK+rcx*8], rax
  |  dispatch_next
  |->op_kshort:
  |  movzx eax, word [PC+2]
  |  movzx ecx, byte [PC+1]
  |  mov qword [STACK+rcx*8], rax
  |  dispatch_next
  |->op_ret:
  |  movzx eax, byte [PC+1]
  |  mov rcx, qword [STACK+rax*8]
  |  lea rax, [STACK-8]
  |  mov PC, qword [STACK-8]
  |  movzx r8d, byte [PC-3]
  |  shl r8d, 3
  |  sub rax, r8
  |  mov qword [STACK-8], rcx
  |  movzx ecx, byte [PC]
  |  mov r8, qword [DISPATCH+rcx*8]
  |  mov STACK, rax
  |  jmp r8
  |->op_lookup:
  |  movzx eax, word [PC+2]
  |  shl eax, 2
  |  lea rcx, [PC]
  |  sub rcx, rax
  |  mov rax, qword [rcx]
  |  sub rax, SYMBOL_TAG
  |  mov rax, qword [rax+SYMBOL_VAL_OFF]
  |  movzx ecx, byte [PC+1]
  |  mov qword [STACK+rcx*8], rax
  |  dispatch_next
  |->op_func:
  /* |  mov rax, PC */
  /* |  shr rax, 3 */
  /* |  and eax, HOTMAP_MASK */
  /* |  lea rcx, [rip+hotmap] */
  /* |  add rcx, rax */
  /* |  movzx r8d, byte [rcx] */
  /* |  mov r9d, r8d */
  /* |  sub r9d, 1 */
  /* |  mov byte [rcx], r9b */
  /* |  movzx eax, byte [rip+max_trace] */
  /* |  test eax, eax */
  /* |  jle >1 */
  /* |  cmp r8b, r9b */
  /* |  jnb >1 */
  /* |  mov byte [rcx], HOTMAP_CNT */
  /* |1: */
  |  dispatch_next
  |->op_lt:
  |  movzx eax, byte [PC+2]
  |  mov rax, qword [STACK+rax*8]
  |  movzx ecx, byte [PC+3]
  |  mov rcx, qword [STACK+rcx*8]
  |  sar rax, 3
  |  sar rcx, 3
  |  xor r8d, r8d
  |  cmp rax, rcx
  |  setl r8b
  |  shl r8d, 8
  |  or r8, 4
  |  movzx eax, byte [PC+1]
  |  mov qword [STACK+rax*8], r8
  |  dispatch_next
  |->op_closure_get:
  |  movzx eax, byte [PC+2]
  |  mov rax, qword [STACK+rax*8]
  |  movzx ecx, byte [PC+3]
  |  sub rax, CLOSURE_TAG
  |  mov rax, qword [rax+rcx*8+CLOSURE_V_OFF]
  |  movzx ecx, byte [PC+1]
  |  mov qword [STACK+rcx*8], rax
  |  dispatch_next
  |->op_lcall:
  |  movzx eax, byte [PC+1]
  |  mov rcx, qword [STACK+rax*8]
  |  add PC, 4
  |  mov qword [STACK+rax*8], PC
  |  lea STACK, [STACK+rax*8]
  |  add STACK, 8
  |  lea r8, [rcx-PTR_TAG]
  |  mov r9, qword [r8+BC_CONST_CNT_OFF]
  |  shl r9, 3
  |  lea PC, [r8+BC_DATA_OFF]
  |  add PC, r9
  |  movzx eax, byte [PC]
  |  mov rax, qword [DISPATCH+rax*8]
  |  jmp rax
  |->op_halt:
  |  mov rax, qword [STACK]
  |  ret

  auto sz = link_and_encode(&d);
  dasm_free(&d);

  /* printf("Ptr is: %p\n", labels[lbl_op_sub]); */
  disassemble(labels[lbl_op_func], sz);
  printf("Replacing impl!\n");
  impls[OP_SUB] = labels[lbl_op_sub];
  impls[OP_ADD] = labels[lbl_op_add];
  impls[OP_CONST] = labels[lbl_op_const];
  impls[OP_KSHORT] = labels[lbl_op_kshort];
  impls[OP_RET] = labels[lbl_op_ret];
  impls[OP_LOOKUP] = labels[lbl_op_lookup];
  impls[OP_FUNC] = labels[lbl_op_func];
  impls[OP_LT] = labels[lbl_op_lt];
  impls[OP_CLOSURE_GET] = labels[lbl_op_closure_get];
  impls[OP_LCALL] = labels[lbl_op_lcall];
  impls[OP_HALT] = labels[lbl_op_halt];
}

/* int main() { */
/*   build_interpreter(); */
/*   return 0; */
/* } */
