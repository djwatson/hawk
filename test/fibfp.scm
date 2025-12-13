(define (fibfp n)
  (if (< n 2.)
      n
      (+ (fibfp (- n 1.))
         (fibfp (- n 2.)))))

(define (run i)
  (if (= i 10)
      1
      (begin
	(fibfp 35.0)
	(run (+ i 1)))))
(run 0)
;(display (fibfp 35.0))

