; Regression test for AArch64 large-offset stores.
; Address generation must preserve the value register while materializing a
; large offset. Otherwise vector-set! can store the offset instead of 'hello.
(define v (make-vector 513 #f))
(do ((i 0 (+ i 1)))
    ((= i 100000) (display (eq? (vector-ref v 512) 'hello)))
  (vector-set! v 512 'hello))
