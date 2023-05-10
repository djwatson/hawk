(define (lt a b) (< a b))
(define (sub a b) (- a b))
(define (add a b) (+ a b))

(define (fib n)
	      (if (lt n 2) n
		  (add
		   (fib (sub n 1))
		   (fib (sub n 2)))))
(fib 40)



