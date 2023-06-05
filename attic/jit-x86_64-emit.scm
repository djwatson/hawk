(define rax 0)
(define rcx 1)
(define rdx 2)
(define rbx 3)
(define rsp 4)
(define rbp 5)
(define rsi 6)
(define rdi 7)
(define r8 8)
(define r9 9)
(define r10 10)
(define r11 11)
(define r12 12)
(define r13 13)
(define r14 14)
(define r15 15)
(define arg-regs (list rdi rsi rdx rcx r8 r9))
(define return-reg rax)
(define (emit-rex c w r x b)
  (set-code-byte!
    c
    (bitwise-ior
      #x40
      (arithmetic-shift w 3)
      (arithmetic-shift r 2)
      (arithmetic-shift x 1)
      b)))

(define (emit-modrm c mod reg rm)
  (set-code-byte!
    c
    (bitwise-ior
      (arithmetic-shift mod 6)
      (arithmetic-shift reg 3)
      rm)))

(define (emit-sib c scale index base)
  (set-code-byte!
    c
    (bitwise-ior
      (arithmetic-shift scale 6)
      (arithmetic-shift (bitwise-and #x7 index) 3)
      (bitwise-and #x7 base))))

(define (emit-fixup c address rel32)
  (let ((cur (get-code-offset c)))
    (set-code-offset! c address)
    (emit-imm32 c (- rel32 (+ 4 (get-code-offset c))))
    (set-code-offset! c cur)))

(define (emit-imm64 c imm)
  (do ((shift 0 (+ 8 shift)))
      ((= shift 64))
    (set-code-byte! c (arithmetic-shift imm (- shift)))))

(define (emit-imm32 c imm)
  (do ((shift 0 (+ 8 shift)))
      ((= shift 32))
    (set-code-byte! c (arithmetic-shift imm (- shift)))))

;; Actual opcodes
;; This one is special, last 3 bits of reg are in opcode.
(define (emit-mov64 c r imm)
  (emit-rex c 1 0 0 (arithmetic-shift r -3))
  (set-code-byte! c (bitwise-ior #xb8 (bitwise-and #x7 r)))
  (emit-imm64 c imm))

(define (emit-call-indirect c r)
  ;(if (>= r 8)
  (emit-rex c 1 0 0 (arithmetic-shift r -3))
  (set-code-byte! c #xff)
  (emit-modrm c #x3 #x2 (bitwise-and #x7 r)))

(define (emit-call32 c label)
  (set-code-byte! c #xe8)
  (emit-label-offset c label))

(define (emit-label-offset c label)
  (emit-imm32
    c
    (-
      (get-label-offset c label)
      (+ 4 (get-code-offset c)))))

(define (emit-ret c)
  (set-code-byte! c #xc3))

(define (emit-cmp-reg-imm32 c r imm)
  (emit-rex c 1 0 0 (arithmetic-shift r -3))
  (set-code-byte! c #x81)
  (emit-modrm c #x3 #x7 (bitwise-and #x7 r))
  (emit-imm32 c imm))

(define (emit-cmp-reg-reg c src dst)
  (emit-rex
    c
    1
    (arithmetic-shift src -3)
    0
    (arithmetic-shift dst -3))
  (set-code-byte! c #x3b)
  (emit-modrm
    c
    #x3
    (bitwise-and #x7 src)
    (bitwise-and #x7 dst)))

;; TODO all versions
(define (emit-set-lt-reg c reg)
  (emit-rex c 1 0 0 (arithmetic-shift reg -3))
  (set-code-byte! c #x0f)
  (set-code-byte! c #x9C)
  (emit-modrm c #x3 0 (bitwise-and #x7 reg)))

(define (emit-jcc32 c cond rel32)
  (set-code-byte! c #x0f)
  (set-code-byte!
    c
    (case cond
      ('ja #x87)
      ('jae #x83)
      ('jb #x82)
      ('jbe #x86)
      ('jc #x82)
      ('je #x84)
      ('jz #x84)
      ('jg #x8f)
      ('jge #x8d)
      ('jl #x8c)
      ('jle #x8e)
      ('jna #x86)
      ('jnae #x82)
      ('jnb #x83)
      ('jnc #x83)
      ('jne #x85)
      ('jng #x8e)
      ('jnge #x8c)
      ('jnl #x8d)
      ('jnle #x8f)
      ('jno #x81)
      ('jnp #x8b)
      ('jns #x89)
      ('jnz #x85)
      ('jo #x80)
      ('jp #x8a)
      ('jpe #x8a)
      ('jpo #x8b)
      ('js #x88)
      ('jz #x84)
      (else (error "Unknown jcc"))))
  (emit-label-offset c rel32))

(define (emit-jmp32 c rel32)
  (set-code-byte! c #xe9)
  (emit-label-offset c rel32))

(define (emit-reg-reg c opcode src dest)
  (emit-rex
    c
    1
    (arithmetic-shift src -3)
    0
    (arithmetic-shift dest -3))
  (set-code-byte! c opcode)
  (emit-modrm
    c
    #x3
    (bitwise-and #x7 src)
    (bitwise-and #x7 dest)))

(define (emit-mem-reg c opcode offset r1 r2)
  (if (eq? (bitwise-and #x7 r1) rsp) 
    (emit-mov-mem-reg-sib c offset 0 r1 r1 r2)
    (begin
      (emit-rex
        c
        1
        (arithmetic-shift r2 -3)
        0
        (arithmetic-shift r1 -3))
      (set-code-byte! c opcode)
      (emit-modrm
        c
        #x2
        (bitwise-and #x7 r2)
        (bitwise-and #x7 r1))
      (emit-imm32 offset))))

(define (emit-mem-reg-sib c opcode offset scale index base reg)
  (emit-rex
    c
    1
    (arithmetic-shift reg -3)
    (arithmetic-shift index -3)
    (arithmetic-shift base -3))
  (set-code-byte! c opcode)
  (emit-modrm c #x2 (bitwise-and #x7 reg) #x4)
  (emit-sib c scale index base)
  (emit-imm32 c offset))

;; Actual opcode defs
(define (emit-add-reg-reg c src dest)
  (emit-reg-reg c #x01 src dest))

(define (emit-xchg-reg-reg c src dest)
  (emit-reg-reg c #x87 src dest))

(define (emit-mov-reg-reg c src dest)
  (emit-reg-reg c #x89 src dest))

(define (emit-mov-mem-reg c offset src dest)
  (emit-mem-reg c #x8b offset src dest))

(define (emit-mov-mem-reg-sib c offset scale index base dest)
  (emit-mem-reg-sib c #x8b offset scale index base dest))

(define (emit-mov-reg-mem c offset src dest)
  (emit-mem-reg c #x89 offset src dest))

(define (emit-mov-reg-mem-sib c offset scale index base dest)
  (emit-mem-reg-sib c #x89 offset scale index base dest))

(define (emit-add-reg-imm32 c src imm32)
  (display "ADD REG IMM32 ") (display imm32) (newline)
  (emit-reg-reg c #x81 0 src)
  (emit-imm32 c imm32))

(define (emit-sub-reg-imm32 c src imm32)
  (emit-reg-reg c #x81 5 src)
  (emit-imm32 c imm32))

(define (emit-ashr-reg-imm8 c src imm8)
  (emit-reg-reg c #xC1 7 src)
  (set-code-byte! c imm8))

(define (emit-shl-reg-imm8 c src imm8)
  (emit-reg-reg c #xC1 4 src)
  (set-code-byte! c imm8))

(define (emit-nop c)
  (set-code-byte! c #x90))

(define (emit-xor-reg-reg c src dest)
  (emit-reg-reg c #x33 src dest))

(define (emit-test-reg-reg c r1 r2)
  (emit-reg-reg c #x85 r1 r2))

;; Both contain special modrm
(define (emit-push c r)
  (emit-rex c 1 0 0 (arithmetic-shift r -3))
  (set-code-byte! c #xff)
  (emit-modrm c #x3 6 (bitwise-and #x7 r)))

(define (emit-pop c r)
  (emit-rex c 1 0 0 (arithmetic-shift r -3))
  (set-code-byte! c #x8f)
  (emit-modrm c #x3 0 (bitwise-and #x7 r)))

(define (emit-lea c offset src dest)
  (emit-mem-reg c #x8d offset src dest))

(define (emit-lea-sib c offset scale index base dest)
  (emit-mem-reg-sib c #x8d offset scale index base dest))

