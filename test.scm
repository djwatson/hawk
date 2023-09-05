(define b '())
(define c (make-vector 3000 2))
(do ((i 0 (+ 1 i)))
    ((= i 30000))
					;(set! b (call-with-current-continuation (lambda (cont) (cont i))))
  (set! b (vector-ref '#(1 2 3) 2))
  )
(write b )



