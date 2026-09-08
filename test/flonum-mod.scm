(import (scheme base) (scheme write) (scheme process-context)
        (prefix (hawk sys) sys:))

(define constant-result
  (let loop ((i 0) (x 1000.0) (sum 0.0))
    (if (= i 1000)
        sum
        (loop (+ i 1) (+ x 1.0) (+ sum (sys:MOD x 7.0))))))

(define variable-result
  (let loop ((i 0) (x 1000.0) (divisor 7.0) (sum 0.0))
    (if (= i 1000)
        sum
        (loop (+ i 1) (+ x 1.0) (- 15.0 divisor)
              (+ sum (sys:MOD x divisor))))))

(unless (and (= constant-result 2998.0) (= variable-result 3501.0))
  (write (list constant-result variable-result))
  (newline)
  (exit 1))
(display "flonum-mod passed\n")
