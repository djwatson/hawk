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
	mov r15, [rsp+8]
	mov [r15], rdi
	add rsp, 16
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbx
	ret
