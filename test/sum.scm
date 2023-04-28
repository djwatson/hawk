(define (loop n sum)
  (if (< n 0)
      sum
      (loop (- n 1) (+ n sum))))

(loop 1000000000 0)
