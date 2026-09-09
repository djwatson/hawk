(import (scheme base) (scheme write))

(define pass-count 0)
(define fail-count 0)

(define-syntax check
  (syntax-rules ()
    ((_ expr expected)
     (let ((result expr))
       (if (equal? result expected)
           (set! pass-count (+ pass-count 1))
           (begin
             (set! fail-count (+ fail-count 1))
             (display "FAIL: ")
             (write 'expr)
             (display " expected ")
             (write expected)
             (display " got ")
             (write result)
             (newline)))))))

;; Basic bitwise-and
(check (bitwise-and 0 0) 0)
(check (bitwise-and 0 1) 0)
(check (bitwise-and 1 0) 0)
(check (bitwise-and 1 1) 1)
(check (bitwise-and #b1010 #b1100) #b1000)
(check (bitwise-and #xff #x0f) #x0f)
(check (bitwise-and -1 1) 1)
(check (bitwise-and -1 -1) -1)

;; Basic bitwise-ior
(check (bitwise-ior 0 0) 0)
(check (bitwise-ior 0 1) 1)
(check (bitwise-ior 1 0) 1)
(check (bitwise-ior 1 1) 1)
(check (bitwise-ior #b1010 #b1100) #b1110)
(check (bitwise-ior -1 0) -1)

;; Basic bitwise-xor
(check (bitwise-xor 0 0) 0)
(check (bitwise-xor 0 1) 1)
(check (bitwise-xor 1 0) 1)
(check (bitwise-xor 1 1) 0)
(check (bitwise-xor #b1010 #b1100) #b0110)
(check (bitwise-xor -1 0) -1)
(check (bitwise-xor -1 -1) 0)

;; Bitwise-not
(check (bitwise-not 0) -1)
(check (bitwise-not 1) -2)
(check (bitwise-not -1) 0)
(check (bitwise-not #x7f) #xffffff80)  ;; assuming 32-bit
(check (bitwise-not (bitwise-not 42)) 42)

;; Multi-argument forms
(check (bitwise-and 1 2 3) 0)
(check (bitwise-and #xff #x7f #x3f) #x2f)
(check (bitwise-ior 1 2 4) 7)
(check (bitwise-ior 1 2 4 8) 15)
(check (bitwise-xor 1 2 3) 0)

;; ash (arithmetic shift)
(check (ash 1 0) 1)
(check (ash 1 1) 2)
(check (ash 1 8) 256)
(check (ash 256 -8) 1)
(check (ash -1 1) -2)
(check (ash -1 -1) -1)
(check (ash #b1010 2) #b101000)
(check (ash #b101000 -3) #b1010)

;; bit-set?
(check (bit-set? 0 0) #t)
(check (bit-set? 1 0) #f)
(check (bit-set? 0 1) #t)
(check (bit-set? 3 #b1010) #t)
(check (bit-set? 2 #b1010) #f)
(check (bit-set? 0 -1) #t)

;; bit-count
(check (bit-count 0) 0)
(check (bit-count 1) 1)
(check (bit-count #b1010) 2)
(check (bit-count #b1111) 4)
(check (bit-count -1) 0)  ;; two's complement: all bits set

;; integer-length
(check (integer-length 0) 0)
(check (integer-length 1) 1)
(check (integer-length 2) 2)
(check (integer-length 3) 2)
(check (integer-length 255) 8)
(check (integer-length 256) 9)
(check (integer-length -1) 0)

;; bitwise-bit-field
(check (bitwise-bit-field #b10110011 0 2) #b11)
(check (bitwise-bit-field #b10110011 2 5) #b001)
(check (bitwise-bit-field #b10110011 0 8) #b10110011)

;; bitwise-copy-bit
(check (bitwise-copy-bit #b1010 0 1) #b1011)
(check (bitwise-copy-bit #b1010 1 0) #b1000)
(check (bitwise-copy-bit 0 3 1) #b1000)

;; Negative number tests
(check (bitwise-and -256 255) 0)
(check (bitwise-ior -256 255) -1)
(check (bitwise-not (bitwise-not -42)) -42)

;; Identity
(check (bitwise-and x x) x)
(let ((x 42)) (check (bitwise-ior x 0) x))
(let ((x 42)) (check (bitwise-xor x x) 0))
(let ((x #b1010)) (check (bitwise-and x -1) x))
(let ((x #b1010)) (check (bitwise-ior x 0) x))

;; Result
(newline)
(display "Bitwise: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
