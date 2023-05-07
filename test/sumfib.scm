(define (fib n)
	      (if (< n 2) n
		  (+
		   (fib (- n 1))
		   (fib (- n 2)))))
(define (loop n sum)
  (if (< n 0)
      sum
      (loop (- n 1) (+ n (fib 30)))))

(loop 1000 0)



