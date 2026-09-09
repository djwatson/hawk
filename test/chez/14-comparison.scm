(import (scheme base) (scheme write))

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

;; Fixnum comparisons
(check (< 1 2) #t)
(check (< 2 1) #f)
(check (< 1 1) #f)
(check (<= 1 2) #t)
(check (<= 1 1) #t)
(check (<= 2 1) #f)
(check (> 2 1) #t)
(check (> 1 2) #f)
(check (> 1 1) #f)
(check (>= 2 1) #t)
(check (>= 1 1) #t)
(check (>= 1 2) #f)

;; Bignum comparisons
(check (< 1000000000000 1000000000001) #t)
(check (> 1000000000001 1000000000000) #t)
(check (= 1000000000000 1000000000000) #t)

;; Flonum comparisons
(check (< 1.0 2.0) #t)
(check (> 2.0 1.0) #t)
(check (= 1.0 1.0) #t)
(check (<= 1.0 1.0) #t)
(check (>= 1.0 1.0) #t)

;; Cross-type comparisons
(check (< 1 2.0) #t)
(check (< 1.0 2) #t)
(check (> 2 1.0) #t)
(check (> 2.0 1) #t)
(check (= 1 1.0) #t)
(check (= 1.0 1) #t)

;; Bignum vs fixnum
(check (< 1 1000000000000) #t)
(check (> 1000000000000 1) #t)

;; Bignum vs flonum
(check (< 1.0 1000000000000.0) #t)

;; Ratnum comparisons
(check (< 1/3 1/2) #t)
(check (> 1/2 1/3) #t)
(check (= 1/2 2/4) #t)

;; Ratnum vs integer
(check (< 1/3 1) #t)
(check (> 1 1/3) #t)
(check (= 1 1/1) #t)

;; Ratnum vs flonum
(check (< 1/3 0.5) #t)

;; Transitivity: a < b and b < c implies a < c
(check (let ((a 1) (b 2) (c 3))
         (and (< a b) (< b c) (< a c)))
       #t)

;; Transitivity across types
(check (let ((a 1) (b 1.5) (c 2))
         (and (< a b) (< b c) (< a c)))
       #t)

;; Mixed exact/inexact
(check (= 1 1.0) #t)
(check (< 1 1.1) #t)
(check (> 1.1 1) #t)

;; Large bignums
(let ((a 999999999999999999)
      (b 1000000000000000000))
  (check (< a b) #t)
  (check (> b a) #t)
  (check (= a a) #t))

;; Comparison with zero
(check (< -1 0) #t)
(check (> 1 0) #t)
(check (< 0 1) #t)
(check (> 0 -1) #t)

;; Negative comparisons
(check (< -2 -1) #t)
(check (> -1 -2) #t)
(check (= -1 -1) #t)

;; Result
(newline)
(display "Comparison: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
