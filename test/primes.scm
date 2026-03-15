;;; PRIMES -- Compute primes less than 100, written by Eric Mohr.

;;; LC NOTE : Can't compute more primes because of heap/stack overflow
(import (scheme r5rs))

(define (interval-list m n)
  (if (> m n) '() (cons m (interval-list (+ 1 m) n))))

(define (remove-multiples n l)
  (if (null? l)
      '()
      (if (= (modulo (car l) n) 0)
          (remove-multiples n (cdr l))
          (cons (car l) (remove-multiples n (cdr l))))))

(define (sieve l)
  (if (null? l) '() (cons (car l) (sieve (remove-multiples (car l) (cdr l))))))

(define (primes<= n) (sieve (interval-list 2 n)))

(define (pp x) (display x) (display "\n"))
;; (pp (primes<= 0))
;; (pp (primes<= 1))
;; (pp (primes<= 50))
;; (pp (primes<= 80))
(define (run-loop n res) (if (= n 0) res (run-loop (- n 1) (primes<= 1000))))
(pp (run-loop 10000 0))

;()
;()
;(2 3 5 7 11 13 17 19 23 29 31 37 41 43 47)
;(2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79)


