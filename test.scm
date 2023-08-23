(define g 'foo)
(do ((i 0 (+ i 1)))
    ((= i 300) 0)
  (set! g (vector 1 2 3)))
(display g)


