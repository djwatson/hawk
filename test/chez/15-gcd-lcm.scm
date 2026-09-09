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

;; Basic GCD
(check (gcd 0 0) 0)
(check (gcd 12 8) 4)
(check (gcd 8 12) 4)
(check (gcd 17 13) 1)
(check (gcd 100 75) 25)

;; GCD with negative arguments
(check (abs (gcd -12 8)) 4)
(check (abs (gcd 12 -8)) 4)
(check (abs (gcd -12 -8)) 4)

;; GCD with one argument
(check (gcd 12) 12)
(check (gcd -12) 12)

;; GCD with multiple arguments
(check (gcd 12 8 4) 4)
(check (gcd 12 8 6) 2)

;; GCD with exact rationals
(check (gcd 1/2 1/3) 1/6)
(check (gcd 3/4 1/2) 1/4)

;; Basic LCM
(check (lcm 0 0) 0)
(check (lcm 12 8) 24)
(check (lcm 8 12) 24)
(check (lcm 7 13) 91)
(check (lcm 100 75) 300)

;; LCM with negative arguments
(check (abs (lcm -12 8)) 24)
(check (abs (lcm 12 -8)) 24)
(check (abs (lcm -12 -8)) 24)

;; LCM with one argument
(check (lcm 12) 12)
(check (lcm -12) 12)

;; LCM with multiple arguments
(check (lcm 2 3 4) 12)
(check (lcm 4 6 8) 24)

;; LCM with exact rationals
(check (lcm 1/2 1/3) 1)
(check (lcm 1/4 1/2) 1/2)

;; GCD and LCM relationship: gcd * lcm = product (for positive ints)
(check (* (gcd 12 8) (lcm 12 8)) (* 12 8))
(check (* (gcd 15 25) (lcm 15 25)) (* 15 25))

;; GCD of a number with itself
(check (gcd 42 42) 42)

;; GCD with zero
(check (gcd 0 5) 5)
(check (gcd 5 0) 5)

;; LCM with zero
(check (lcm 0 5) 0)
(check (lcm 5 0) 0)

;; Result
(newline)
(display "GCD/LCM: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
