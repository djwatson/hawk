(import (scheme r5rs))

(define (run i sum)
  (if (< i 0.)
      sum
      (run (- i 1.) (+ i sum))))

(define (doit i sum)
  (if (= i 0)
      sum
      (begin
	(doit (- i 1) (+ sum (run 1e6 0.0))))))

;(display (run 1e9 0.0))
(display (doit 500 0.0))


