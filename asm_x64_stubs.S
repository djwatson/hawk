	.intel_syntax noprefix
	.global jit_entry_stub, jit_exit_stub

	.text
jit_entry_stub:
	push rbx
	push r12
	push r13
	push r14
	push r15
	push rdi
	push rsi
	mov rdi, [rdi]
	jmp rdx

jit_exit_stub:
	mov r15, [rsp+24]
	mov [r15], rdi

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
	
	add rsp, 128
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	ret
