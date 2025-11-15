(define (fibfp n)
  (if (< n 2.)
      n
      (+ (fibfp (- n 1.))
         (fibfp (- n 2.)))))

(display (fibfp 40))
