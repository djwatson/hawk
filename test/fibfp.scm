
(define (fibfp n)
  (if (< n 2.)
      n
      (+ (fibfp (- n 1.))
         (fibfp (- n 2.)))))

(define (run i res)
  (if (= i 10)
      res
      (run (+ i 1) (fibfp 35.0))))
(display (run 0 0))

