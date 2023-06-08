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
	mov rbx, [r15 + 8]
	mov rcx, [r15 + 16]
	mov rdx, [r15 + 24]
	mov rsi, [r15 + 32]
	mov r8, [r15 + 40]
	mov r9, [r15 + 48]
	mov r10, [r15 + 56]
	mov r11, [r15 + 64]
	mov r12, [r15 + 72]
	mov r13, [r15 + 80]
	mov r14, [r15 + 88]
	
	pop r15
	jmp r15

jit_exit_stub:
//  Push trace
	mov r15, [rsp+24]
	mov [r15], rdi

//  Push reg state
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rsi
	push rdx
	push rcx
	push rbx
	push rax

	lea rdi, [rsp]
	call exit_stub_frame_restore

//  pop reg state
	add rsp, 128
// pop callee-saved
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	ret
