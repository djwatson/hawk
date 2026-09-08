; Regression test for AArch64 multi-instruction MOVN constants.
; MOVN receives complemented chunks for its initial instruction, but each
; following MOVK must receive the original value chunk. This loop forces the
; constant into JIT code and stores it repeatedly through a vector operation.
; The expected value also exercises MOVN/MOVK instruction-cost selection.
(define v (make-vector 1 0))
(do ((i 0 (+ i 1)))
    ((= i 100000) (display (vector-ref v 0)))
  (vector-set! v 0 -32682016773425))
