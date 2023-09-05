(define b '())
(do ((i 0 (+ 1 i)))
    ((= i 30000))
  (set! b (call-with-current-continuation (lambda (cont) (cont i)))))
(write b )



