
(define (foo x . rest)
  (if (= x 0) 0
      (begin
	($write rest current-output-port-internal)
	(foo (- x 1) (car rest)))))

(foo 1000 'a)
