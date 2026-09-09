; A mixed comparison must keep checking that dynamic fixnums are exactly
; representable as doubles after the trace has been recorded.
(define v (make-vector 1000 9007199254740992))
(do ((i 500 (+ i 1)))
    ((= i 1000))
  (vector-set! v i 9007199254740993))

(define count
  (do ((i 0 (+ i 1))
       (n 0 (if (= (vector-ref v i) 9007199254740992.0)
                (+ n 1)
                n)))
      ((= i 1000) n)))

(display count)
(newline)
