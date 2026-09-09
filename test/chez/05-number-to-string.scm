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

;; Default radix (10)
(check (number->string 0) "0")
(check (number->string 1) "1")
(check (number->string -1) "-1")
(check (number->string 42) "42")
(check (number->string -42) "-42")

;; Radix 2 (binary)
(check (number->string 0 2) "0")
(check (number->string 1 2) "1")
(check (number->string 2 2) "10")
(check (number->string 255 2) "11111111")
(check (number->string -5 2) "-101")

;; Radix 8 (octal)
(check (number->string 0 8) "0")
(check (number->string 7 8) "7")
(check (number->string 8 8) "10")
(check (number->string 255 8) "377")
(check (number->string -8 8) "-10")

;; Radix 16 (hexadecimal)
(check (number->string 0 16) "0")
(check (number->string 10 16) "A")
(check (number->string 15 16) "F")
(check (number->string 16 16) "10")
(check (number->string 255 16) "FF")
(check (number->string -255 16) "-FF")

;; Radix 10 (explicit)
(check (number->string 42 10) "42")

;; Exact integers round-trip
(let ((n 123456789))
  (check (string->number (number->string n) 10) n))

(let ((n 255))
  (check (string->number (number->string n 2) 2) n)
  (check (string->number (number->string n 8) 8) n)
  (check (string->number (number->string n 16) 16) n))

;; Negative numbers round-trip
(let ((n -255))
  (check (string->number (number->string n 2) 2) n)
  (check (string->number (number->string n 16) 16) n))

;; Large numbers
(let ((n 1000000000000))
  (check (string->number (number->string n)) n)
  (check (string->number (number->string n 16) 16) n))

;; Zero in all radices
(check (number->string 0 2) "0")
(check (number->string 0 8) "0")
(check (number->string 0 16) "0")

;; Exact rationals (if supported)
(let ((r 1/3))
  (check (number? (string->number (number->string r))) #t))

;; Result
(newline)
(display "Number->string: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
