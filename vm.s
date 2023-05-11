global INS_FUNC
global INS_KSHORT
global INS_JMP
global INS_SUBVN
global INS_ADDVV
global INS_JISLT
global INS_GGET
global INS_CALLT
extern FAIL_SLOWPATH
extern hotmap

;;; rdi, rsi, rdx, rcx,  r8,            r9
;;; ra,  pc,  rd, frame, op_table_arg
section .data

	section .text

FIXMAP:
	mov r11, rsi
	shr r11, 2
	and r11, 63
	add byte [hotmap + r11], 128
	jmp INS_CALLT.donefix

INS_CALLT:
	;; Hotmap
	mov r11, rsi
	shr r11, 2
	and r11, 63
	sub byte [hotmap + r11], 2
	jb FIXMAP
.donefix:
	;; Typecheck closure
	mov rax, [rcx + rdi*8]
	mov r11, rax
	and r11, 7
	cmp r11, 5
	jne FAIL_SLOWPATH

	mov [rcx - 8], rax
	;; SET PC
	mov rsi, [rax-5]

;;; Copy loop
	sub rdx, 1
	jz .endloop
	lea r11, [rcx + rdi * 8 + 8]
	mov rdi, rcx

.loop:
	mov rax, [r11]
	add r11, 8
	mov [rdi], rax
	add rdi, 8
	sub rdx, 1
	ja .loop
.endloop:

	mov edx, [rsi]
	movzx r11d, dl
	movzx edi, dh
	shr edx, 10h
	jmp [r8 + r11 *8]

INS_GGET:
	mov rax, [rcx-8] 	;pull func from frame (-5)
	mov rax, [rax+rdx*8+27] 	;pull vector from bcfunc (-5)

	mov rax, [rax] 	;pull in sym val
	cmp rax, 27
	je FAIL_SLOWPATH

	mov [rcx + rdi*8], rax
	
	mov edx, [rsi+4]
	movzx r11d, dl
	movzx edi, dh
	add rsi, 4
	shr edx, 10h
	jmp [r8 + r11 *8]

INS_SUBVN:
	movzx r11d, dl 		;rb
	movzx eax, dh 		;rc

	mov r9, [rcx + r11*8]
	test r9b,7
	jne FAIL_SLOWPATH

	sal rax, 3
	sub r9, rax
	jo FAIL_SLOWPATH
	mov [rcx + rdi*8],r9
	
	mov edx, [rsi+4]
	movzx r11d, dl
	movzx edi, dh
	add rsi, 4
	shr edx, 10h
	jmp [r8 + r11 *8]

INS_ADDVV:
	movzx r11d, dl 		;rb
	movzx eax, dh 		;rc

	mov r9, [rcx + r11*8]
	mov r10, [rcx + rax*8]
	mov r11, r10
	or r11, r9
	test r11b,7
	jne FAIL_SLOWPATH

	add r9, r10
	jo FAIL_SLOWPATH
	mov [rcx + rdi*8],r9
	
	mov edx, [rsi+4]
	movzx r11d, dl
	movzx edi, dh
	add rsi, 4
	shr edx, 10h
	jmp [r8 + r11 *8]

INS_JISLT:
	movzx r11d, dl 		;rb
	movzx eax, dh 		;rc

	mov r9, [rcx + r11*8]
	mov r10, [rcx + rax*8]
	mov r11, r10
	or r11, r9
	test r11b,7
	jne FAIL_SLOWPATH

	xor r11, r11
	cmp r9,r10
	setl r11b
	lea rsi, [rsi+r11*4]
	
	mov edx, [rsi+4]
	movzx r11d, dl
	movzx edi, dh
	add rsi, 4
	shr edx, 10h
	jmp [r8 + r11 *8]

INS_FUNC:
	mov edx, [rsi+4]
	movzx r11d, dl
	movzx edi, dh
	add rsi, 4
	shr edx, 10h
	jmp [r8 + r11 *8]

INS_JMP:
;;; TODO all should be like this without rsi adjust
	mov edx, [rsi + rdi*4]
	lea rsi, [rsi + rdi*4]

	movzx r11d, dl
	movzx edi, dh
	shr edx, 10h
	jmp [r8 + r11 *8]

INS_KSHORT:
	mov [rcx + rdi*8], rdx
	
	mov edx, [rsi+4]
	movzx r11d, dl
	movzx edi, dh
	add rsi, 4
	shr edx, 10h
	jmp [r8 + r11 *8]
	

 ;; 	    │      void INS_FUNC(PARAMS) {                                                                                            
 ;; 24.02 │2930:   mov    0x4(%rdx),%eax                                                                                                 
 ;;       │2933:   add    $0x4,%rdx                                                                                                      
 ;;       │2937:   movzbl %al,%esi                                                                                                       
 ;;       │293a:   movzbl %ah,%edi                                                                                                       
 ;; 65.02 │293d:   shr    $0x10,%eax                                                                                                     
 ;;       │2940:   mov    (%r8,%rsi,8),%r9                                                                                               
 ;; 10.96 │2944:   mov    %eax,%esi                                                                                                      
 ;;       │2946: → jmp    *%r9                                                                                                          
                                   
