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

;; Large bignum arithmetic
(let ((big (* 1000000000 1000000000)))
  (check (+ big 1) 1000000000000000001)
  (check (- big 1) 999999999999999999)
  (check (* big 1) big)
  (check (quotient big 1000000000) 1000000000))

;; Very large multiplication
(let ((big (* 999999999999 999999999999)))
  (check (exact? big) #t)
  (check (integer? big) #t))

;; expt edge cases
(check (expt 0 0) 1)
(check (expt 1 0) 1)
(check (expt 1 100) 1)
(check (expt 2 0) 1)
(check (expt 2 10) 1024)
(check (expt 0 1) 0)
(check (expt 0 100) 0)
(check (expt 10 3) 1000)
(check (expt 10 -1) 1/10)
(check (expt 2 -3) 1/8)

;; expt with negative base
(check (expt -1 0) 1)
(check (expt -1 1) -1)
(check (expt -1 2) 1)
(check (expt -1 3) -1)
(check (expt -2 3) -8)
(check (expt -2 4) 16)

;; sqrt of exact squares
(check (exact? (sqrt 0)) #t)
(check (sqrt 0) 0)
(check (sqrt 1) 1)
(check (sqrt 4) 2)
(check (sqrt 9) 3)
(check (sqrt 100) 10)
(check (sqrt 1000000) 1000)

;; sqrt of non-squares (should be inexact)
(check (inexact? (sqrt 2)) #t)
(check (inexact? (sqrt 3)) #t)
(check (inexact? (sqrt 5)) #t)

;; exact-integer-sqrt
(check (exact-integer-sqrt 0) (values 0 0))
(check (exact-integer-sqrt 1) (values 1 0))
(check (exact-integer-sqrt 4) (values 2 0))
(check (exact-integer-sqrt 2) (values 1 1))
(check (exact-integer-sqrt 3) (values 1 2))
(check (exact-integer-sqrt 8) (values 2 4))

;; rationalize
(check (rationalize 1/3 0) 1/3)
(check (rationalize 0.5 0) 0.5)
(check (rationalize 1 0) 1)

;; Bignum division
(let ((big (* 1000000000 1000000000 100)))
  (let ((q (quotient big 100))
        (r (remainder big 100)))
    (check (= (* q 100) (- big r)) #t)))

;; Exact arithmetic consistency
(check (= (+ 1/2 1/2) 1) #t)
(check (= (* 1/3 3) 1) #t)
(check (= (/ 1 3) 1/3) #t)

;; Integer? with bignums
(check (integer? (* 1000000000 1000000000)) #t)
(check (integer? 1/1) #t)
(check (integer? 3/2) #f)

;; exact? with various types
(check (exact? 42) #t)
(check (exact? 1/3) #t)
(check (exact? 42.0) #f)

;; zero? with bignums
(check (zero? 0) #t)
(check (zero? (* 1000000000 0)) #t)
(check (zero? 1) #f)

;; Result
(newline)
(display "Number edge: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
