(import (scheme base) (scheme write) (scheme inexact) (scheme complex))

(define pass-count 0)
(define fail-count 0)

(define (approx-equal? a b)
  (< (abs (- a b)) 1e-10))

(define-syntax check
  (syntax-rules ()
    ((_ expr expected)
     (let ((result expr))
       (if (if (and (inexact? result) (inexact? expected))
               (approx-equal? result expected)
               (equal? result expected))
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

(define-syntax check-nan
  (syntax-rules ()
    ((_ expr)
     (let ((result expr))
       (if (nan? result)
           (set! pass-count (+ pass-count 1))
           (begin
             (set! fail-count (+ fail-count 1))
             (display "FAIL: ")
             (write 'expr)
             (display " expected NaN, got ")
             (write result)
             (newline)))))))

;; sin/cos/tan at special values
(check (sin 0.0) 0.0)
(check (sin -0.0) -0.0)
(check (sin +inf.0) +nan.0)
(check (sin -inf.0) +nan.0)
(check (cos 0.0) 1.0)
(check (cos -0.0) 1.0)
(check (cos +inf.0) +nan.0)
(check (cos -inf.0) +nan.0)
(check (tan 0.0) 0.0)
(check (tan -0.0) -0.0)
(check (tan +inf.0) +nan.0)
(check (tan -inf.0) +nan.0)

;; asin edge cases
(check (asin 0.0) 0.0)
(check (asin 1.0) 1.5707963267948966)  ;; pi/2
(check (asin -1.0) -1.5707963267948966)
(check-nan (asin 2.0))
(check-nan (asin -2.0))

;; acos edge cases
(check (acos 1.0) 0.0)
(check (acos 0.0) 1.5707963267948966)  ;; pi/2
(check (acos -1.0) 3.141592653589793)  ;; pi
(check-nan (acos 2.0))

;; atan edge cases
(check (atan 0.0) 0.0)
(check (atan -0.0) -0.0)
(check (atan +inf.0) 1.5707963267948966)
(check (atan -inf.0) -1.5707963267948966)

;; atan with two arguments (all quadrants)
(check (atan 1.0 1.0) 0.7853981633974483)   ;; pi/4
(check (atan -1.0 1.0) -0.7853981633974483)
(check (atan 1.0 -1.0) 2.356194490192345)    ;; 3*pi/4
(check (atan -1.0 -1.0) -2.356194490192345)
(check (atan 0.0 1.0) 0.0)
(check (atan 0.0 -1.0) 3.141592653589793)
(check (atan 1.0 0.0) 1.5707963267948966)
(check (atan -1.0 0.0) -1.5707963267948966)

;; exp edge cases
(check (exp 0.0) 1.0)
(check (exp -0.0) 1.0)
(check (exp +inf.0) +inf.0)
(check (exp -inf.0) 0.0)
(check-nan (exp +nan.0))

;; log edge cases
(check (log 1.0) 0.0)
(check (log +inf.0) +inf.0)
(check-nan (log +nan.0))
(check (real? (log -1.0)) #t)  ;; should be pi*i

;; log with base
(check (log 8 2) 3.0)
(check (log 100 10) 2.0)

;; sqrt edge cases
(check (sqrt 0.0) 0.0)
(check (sqrt +inf.0) +inf.0)
(check-nan (sqrt -inf.0))
(check-nan (sqrt -1.0))
(check (sqrt 4.0) 2.0)

;; sqrt of exact squares
(check (exact? (exact (sqrt 4))) #t)
(check (= (exact (sqrt 4)) 2) #t)

;; expt edge cases
(check (expt 0.0 0.0) 1.0)
(check (expt 1.0 +inf.0) 1.0)
(check (expt 1.0 +nan.0) 1.0)
(check (expt +inf.0 0.0) 1.0)
(check-nan (expt +nan.0 0.0))
(check (expt 2.0 10.0) 1024.0)

;; Result
(newline)
(display "Transcendental: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
