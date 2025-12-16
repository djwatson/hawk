;(import (scheme r5rs))
(define (loop n sum)
  (if (< n 0)
      sum
      (loop (- n 1) (+ n sum))))
(display (loop 100000000 0))
(display (loop 100000000.0 0.0))
(display (loop 100000000 0))



