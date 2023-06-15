	.intel_syntax noprefix
	.global jit_entry_stub, jit_exit_stub

	.text
jit_entry_stub:
//  Save callee-saved regs.
	push rbx
	push r12
	push r13
	push r14
	push r15

	// RDI: scheme frame ptr.
	push rdx // state regs
	push rsi // ptr to call.

	mov r15, rdx // state regs.

// Put new reg state based on rcx param.
	mov rax, [r15]
	mov rcx, [r15 + 8]
	mov rdx, [r15 + 16]
	mov rbx, [r15 + 24]
	// RSP 32, c stack ptr.
	mov rbp, [r15 + 40]
	mov rsi, [r15 + 48]
	// RDI 56, scheme frame ptr.
	mov r8, [r15 + 64]
	mov r9, [r15 + 72]
	mov r10, [r15 + 88]
	mov r11, [r15 + 96]
	mov r12, [r15 + 104]
	mov r13, [r15 + 112]
	mov r14, [r15 + 120]
	mov r15, [r15 + 128]
	
	pop r15
	jmp r15

jit_exit_stub:
	//  Push reg state
	mov r15, [rsp+16]
	mov [r15 + 116], r15
	mov [r15 + 112], r14
	mov [r15 + 104], r13
	mov [r15 + 96], r12
	mov [r15 + 88], r11
	mov [r15 + 80], r10
	mov [r15 + 72], r9
	mov [r15 + 64], r8
	mov [r15 + 56], rdi
	mov [r15 + 48], rsi
	mov [r15 + 40], rbp
	mov [r15 + 32], rsp
	mov [r15 + 24], rbx
	mov [r15 + 16], rdx
	mov [r15 + 8], rcx
	mov [r15], rax
	pop rax // trace
	mov [r15 + 128], rax
	pop rax // exit num
	mov [r15 + 136], rax

//  pop reg state
	add rsp, 8
// pop callee-saved
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	ret
