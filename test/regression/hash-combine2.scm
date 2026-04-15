;; There is a bug when closures that escape combine with those that
;; don't escape
(import (scheme base) (scheme write))

(define (hash-combine a b) (+ a b))

(define (fold f init lst) init)

(define (test-function field1)
  (define (helper2 vec)
    (let loop ((i 0) (acc 0))
      (if (< i (vector-length vec))
          (loop (+ i 1) (hash-combine acc (opnd->hash (vector-ref vec i))))
          acc)))

  (define (opnd->hash opnd)
    (display "opnd->hash:")
    (display opnd)
    (newline)
    (cond
      ((vector? opnd) (helper2 opnd))
      ((list? opnd) (fold hash-combine 0 (map opnd->hash opnd)))
      (else 999)))

  (opnd->hash field1))

;; Test it with a VECTOR
(display "Testing with vector...\n")
(let ((result (test-function (vector 1 2 3))))
  (display "Result: ")
  (display result)
  (newline))
