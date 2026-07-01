#if defined(__aarch64__) || defined(__arm64__)

.text
.globl  ffi_call_asm
.hidden ffi_call_asm
ffi_call_asm:
  stp x19, x30, [sp, #-16]!
  mov x19, x0

  ldr x0, [x19, #8]
  ldr x1, [x19, #16]
  ldr x2, [x19, #24]
  ldr x3, [x19, #32]
  ldr x4, [x19, #40]
  ldr x5, [x19, #48]

  ldr d0, [x19, #56]
  ldr d1, [x19, #64]
  ldr d2, [x19, #72]
  ldr d3, [x19, #80]
  ldr d4, [x19, #88]
  ldr d5, [x19, #96]

  ldr x16, [x19]
  blr x16

  str x0, [x19, #104]
  str d0, [x19, #112]

  ldp x19, x30, [sp], #16
  ret

#else

.text
.globl  ffi_call_asm
.hidden ffi_call_asm
ffi_call_asm:
  pushq %rbx
  movq  %rdi, %rbx

  movq  8(%rbx), %rdi
  movq  16(%rbx), %rsi
  movq  24(%rbx), %rdx
  movq  32(%rbx), %rcx
  movq  40(%rbx), %r8
  movq  48(%rbx), %r9

  movsd 56(%rbx), %xmm0
  movsd 64(%rbx), %xmm1
  movsd 72(%rbx), %xmm2
  movsd 80(%rbx), %xmm3
  movsd 88(%rbx), %xmm4
  movsd 96(%rbx), %xmm5

  callq *(%rbx)

  movq   %rax, 104(%rbx)
  movsd  %xmm0, 112(%rbx)

  popq %rbx
  ret

#endif
