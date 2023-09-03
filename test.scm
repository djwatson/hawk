(define b '())
(do ((i 0 (+ 1 i)))
    ((= i 30000))
  (set! b (make-vector 10000 'foo)))
(write b )

