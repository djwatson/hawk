;;; FIBFP -- Computes fib(35) using floating point

(define (fibfp n)
  (if (< n 2.)
    n
    (+ (fibfp (- n 1.))
            (fibfp (- n 2.)))))

(let ((result (fibfp 35.)))
  (println (= result 9227465.)))

;#t
