;;; SUMFP -- Compute sum of integers from 0 to 10000 using floating point

(define (run n)
  (let loop ((i n) (sum 0.))
    (if (< i 0.)
      sum
      (loop (- i 1.) (+ i sum)))))

(let ((result (run 10000.)))
  (println (= result 50005000.)))

;#t
