(define (loop n sum)
  (if (< n 0)
      sum
      (loop (- n 1.0) (+ n sum))))

(loop 1000000000.0 0.0)
