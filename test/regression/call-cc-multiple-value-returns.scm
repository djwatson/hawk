
(define (foob)
  (display "TEST1:\n")
  (let-values (((foo1 bar1) (call-with-current-continuation (lambda (thunk) (values 1 2)))))
    (display foo1) (newline)
    (display bar1) (newline))
  (display "TEST2:\n")
  (let-values (((foo1 bar1) (call-with-current-continuation (lambda (thunk) (thunk 1 2)))))
    (display foo1) (newline)
    (display bar1) (newline)))


(do ((i 0 (+ i 1)))
    ((= i 1000))
  (foob))
