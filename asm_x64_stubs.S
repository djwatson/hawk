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
	push rdi
	push rsi
	mov rdi, [rdi]
	push rdx
//  rcx
	mov r15, rcx

// Put new reg state based on rcx param.
	mov rax, [r15]
	mov rcx, [r15 + 8]
	mov rdx, [r15 + 16]
	mov rbx, [r15 + 24]
	// RSP 32
	// RBP 40
	mov rsi, [r15 + 48]
	// RDI 56
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
//  Push trace
	mov r15, [rsp+24]
	mov [r15], rdi

	//  Push reg state
	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rdi
	push rsi
	push rbp
	push rsp
	push rbx
	push rdx
	push rcx
	push rax

	lea rdi, [rsp]
	call exit_stub_frame_restore

//  pop reg state
	add rsp, 160
// pop callee-saved
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	ret
