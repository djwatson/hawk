(define (loop n sum)
  (if (< n 0)
      sum
      (loop (- n 1) (+ n sum))))

(define (fib n)
	      (if (< n 2) (loop 1000 0)
		  (+
		   (fib (- n 1))
		   (fib (- n 2)))))
 (fib 30)



