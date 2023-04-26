;(import (scheme r5rs))
(letrec ((fib (lambda (n)
		(if (< n 2) n
		  (+
		   (fib (- n 1))
		   (fib (- n 2)))))))
  (display (fib 40)))


