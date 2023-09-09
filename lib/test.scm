(define (bar x)
  (letrec ((bar (lambda (x sum)
		  (if (= x 0) sum
		      (begin
			(bar (- x 1) (+ sum x)))))))
    (bar x 0)))
(display (bar 1000000000))
