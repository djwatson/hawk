(import (scheme base) (scheme write) (scheme inexact))

(define pass-count 0)
(define fail-count 0)

(define-syntax check
  (syntax-rules ()
    ((_ expr expected)
     (let ((result expr))
       (if (equal? result expected)
           (set! pass-count (+ pass-count 1))
           (begin
             (set! fail-count (+ fail-count 1))
             (display "FAIL: ")
             (write 'expr)
             (display " expected ")
             (write expected)
             (display " got ")
             (write result)
             (newline)))))))

;; NaN is not equal to anything, including itself
(check (not (= +nan.0 +nan.0)) #t)
(check (not (< +nan.0 1)) #t)
(check (not (> +nan.0 1)) #t)
(check (not (<= +nan.0 1)) #t)
(check (not (>= +nan.0 1)) #t)
(check (not (= 1 +nan.0)) #t)
(check (not (< 1 +nan.0)) #t)
(check (not (> 1 +nan.0)) #t)

;; NaN propagation in arithmetic
(check (nan? (+ +nan.0 1)) #t)
(check (nan? (+ 1 +nan.0)) #t)
(check (nan? (- +nan.0 1)) #t)
(check (nan? (* +nan.0 2)) #t)
(check (nan? (* 2 +nan.0)) #t)
(check (nan? (/ +nan.0 1)) #t)
(check (nan? (/ 1 +nan.0)) #t)
(check (nan? (abs +nan.0)) #t)
(check (nan? (min +nan.0 1)) #t)
(check (nan? (max +nan.0 1)) #t)

;; Signed zero: +0.0 and -0.0 are equal with = but distinct with eqv?
(check (= +0.0 -0.0) #t)
(check (not (eqv? +0.0 -0.0)) #t)

;; Signed zero in comparisons
(check (< -0.0 +0.0) #f)
(check (> -0.0 +0.0) #f)
(check (<= -0.0 +0.0) #t)
(check (>= -0.0 +0.0) #t)

;; Signed zero in arithmetic
(check (= (+ -0.0 -0.0) -0.0) #t)
(check (= (+ +0.0 -0.0) +0.0) #t)
(check (= (+ -0.0 +0.0) +0.0) #t)
(check (= (* -1.0 +0.0) -0.0) #t)
(check (= (* -1.0 -0.0) +0.0) #t)

;; Infinity
(check (= +inf.0 +inf.0) #t)
(check (= -inf.0 -inf.0) #t)
(check (not (= +inf.0 -inf.0)) #t)
(check (> +inf.0 0) #t)
(check (< -inf.0 0) #t)
(check (= (+ +inf.0 1) +inf.0) #t)
(check (= (+ -inf.0 1) -inf.0) #t)
(check (= (* +inf.0 2) +inf.0) #t)
(check (= (* -inf.0 2) -inf.0) #t)

;; Infinity in comparisons with NaN
(check (not (= +inf.0 +nan.0)) #t)
(check (not (> +inf.0 +nan.0)) #t)
(check (not (< -inf.0 +nan.0)) #t)

;; Exact/inexact conversions
(check (inexact? (inexact 1)) #t)
(check (= (inexact 1) 1.0) #t)
(check (exact? (exact 1.0)) #t)
(check (= (exact 1.0) 1) #t)
(check (exact? (exact 0.5)) #t)
(check (= (exact 0.5) 1/2) #t)

;; Subnormal numbers
(let ((sub (inexact (expt 2 -1074))))
  (check (inexact? sub) #t)
  (check (> sub 0) #t)
  (check (< sub (inexact (expt 2 -1022))) #t))

;; Overflow to infinity
(check (infinite? (* 1e308 10)) #t)
(check (infinite? (* -1e308 10)) #t)

;; Underflow to zero
(check (= (* 1e-308 1e-308) 0.0) #t)

;; NaN predicates
(check (nan? +nan.0) #t)
(check (nan? 1.0) #f)
(check (infinite? +inf.0) #t)
(check (infinite? -inf.0) #t)
(check (infinite? +nan.0) #f)
(check (infinite? 1.0) #f)
(check (finite? 1.0) #t)
(check (finite? +nan.0) #f)
(check (finite? +inf.0) #f)

;; Result
(newline)
(display "IEEE: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
