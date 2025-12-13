
(define (run i sum)
  (if (< i 0.)
      sum
      (run (- i 1.) (+ i sum))))

(display (run 1e8 0.0))

