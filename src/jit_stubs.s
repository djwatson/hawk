	.intel_syntax noprefix

	.text
	.globl jit_entry_stub
jit_entry_stub:	
	#  Save callee-saved regs.
	push rbx
	push rbp
	push r12
	push r13
	push r14
	push r15
        # RDI: scheme frame ptr.
	push rdx # state regs
	push rsi # ptr to call
	mov r15, rdx # state reg
        # Put new reg state based on rcx param.
	mov rax, [r15]
	mov rcx, [r15 + 8]
	mov rdx, [r15 + 16]
	mov rbx, [r15 + 24]
        # RSP 32, c stack ptr.
	mov rbp, [r15 + 40]
	mov rsi, [r15 + 48]
        # RDI 56, scheme frame ptr.
	mov r8, [r15 + 64]
	mov r9, [r15 + 72]
	mov r10, [r15 + 80]
	mov r11, [r15 + 88]
	mov r12, [r15 + 96]
	mov r13, [r15 + 104]
	mov r14, [r15 + 112]
	mov r15, [r15 + 120]
	pop r15
	jmp r15

	.globl jit_exit_stub
jit_exit_stub:	
        #  Push reg state
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
	pop rax # trace
	mov [r15 + 128], rax
	pop rax # exit num
	mov [r15 + 136], rax
        #  pop reg state
	add rsp, 8
        # pop callee-saved
	pop r15
	pop r14
	pop r13
	pop r12
	pop rbp
	pop rbx
	ret

# R15 contains the object pointer.
# Save all caller-saved registers, then jmp.
	.globl GC_log_obj_slow
	.globl jit_gc_log	
jit_gc_log:
	push r11
	push r10
	push r9
	push r8
	push rdi
	push rsi
	push rdx
	push rcx
	push rax

	mov rdi, r15
	call GC_log_obj_slow

	pop rax
	pop rcx
	pop rdx
	pop rsi
	pop rdi
	pop r8
	pop r9
	pop r10
	pop r11
	ret

	.globl vm_read_char
	.globl jit_read_char	
jit_read_char:
	push r11
	push r10
	push r9
	push r8
	push rdi
	push rsi
	push rdx
	push rcx
	push rax

	mov rdi, r15
	call vm_read_char
	mov r15, rax

	pop rax
	pop rcx
	pop rdx
	pop rsi
	pop rdi
	pop r8
	pop r9
	pop r10
	pop r11
	ret

	.globl vm_peek_char
	.globl jit_peek_char	
jit_peek_char:
	push r11
	push r10
	push r9
	push r8
	push rdi
	push rsi
	push rdx
	push rcx
	push rax

	mov rdi, r15
	call vm_peek_char
	mov r15, rax

	pop rax
	pop rcx
	pop rdx
	pop rsi
	pop rdi
	pop r8
	pop r9
	pop r10
	pop r11
	ret
