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

;; Basic min/max
(check (min 1 2) 1)
(check (max 1 2) 2)
(check (min 2 1) 1)
(check (max 2 1) 2)
(check (min 1 1) 1)
(check (max 1 1) 1)

;; Multiple arguments
(check (min 3 1 2) 1)
(check (max 3 1 2) 3)
(check (min 5 4 3 2 1) 1)
(check (max 5 4 3 2 1) 5)

;; Negative numbers
(check (min -1 -2) -2)
(check (max -1 -2) -1)
(check (min -5 -4 -3 -2 -1) -5)
(check (max -5 -4 -3 -2 -1) -1)

;; Mixed positive/negative
(check (min -1 1) -1)
(check (max -1 1) 1)

;; With zero
(check (min 0 1) 0)
(check (max 0 1) 1)
(check (min 0 -1) -1)
(check (max 0 -1) 0)

;; Flonums
(check (min 1.0 2.0) 1.0)
(check (max 1.0 2.0) 2.0)
(check (min 1.5 2.5 0.5) 0.5)
(check (max 1.5 2.5 0.5) 2.5)

;; Cross-type (exact/inexact)
(check (= (min 1 2.0) 1.0) #t)
(check (= (max 1 2.0) 2.0) #t)

;; Bignums
(check (min 1000000000000 1000000000001) 1000000000000)
(check (max 1000000000000 1000000000001) 1000000000001)

;; min/max with single argument
(check (min 42) 42)
(check (max 42) 42)

;; NaN propagation (IEEE requirement)
(check (nan? (min +nan.0 1)) #t)
(check (nan? (max +nan.0 1)) #t)
(check (nan? (min 1 +nan.0)) #t)
(check (nan? (max 1 +nan.0)) #t)

;; Infinity
(check (min +inf.0 1) 1.0)
(check (max +inf.0 1) +inf.0)
(check (min -inf.0 1) -inf.0)
(check (max -inf.0 1) 1.0)

;; Result
(newline)
(display "Min/Max: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
