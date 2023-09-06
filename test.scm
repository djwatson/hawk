(define (str . rest) rest)

(define (foo x)
  (if (= x 0) 0
      (begin
	($write (str x) current-output-port-internal)
	(foo (- x 1)))))

(foo 1000)
