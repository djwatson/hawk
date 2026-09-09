(import (scheme base) (scheme write) (scheme char))

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

;; map returns a list
(check (list? (map + '(1 2 3))) #t)
(check (map + '()) '())
(check (map + '(1)) '(1))
(check (map + '(1 2 3) '(4 5 6)) '(5 7 9))

;; map result is freshly allocated (not eqv? to input)
(let ((input (list 1 2 3)))
  (check (eqv? (map + input) input) #f))

;; map with single-element list
(check (map (lambda (x) (* x x)) '(5)) '(25))

;; map with many arguments
(check (map + '(1 2) '(3 4) '(5 6)) '(9 12))

;; map preserves order
(check (map (lambda (x) (* x x)) '(1 2 3 4 5)) '(1 4 9 16 25))

;; map side effects occur in order
(let ((result '()))
  (map (lambda (x) (set! result (cons x result))) '(1 2 3))
  (check result '(3 2 1)))

;; for-each returns unspecified value (we test it doesn't error)
(let ((val (for-each (lambda (x) x) '(1 2 3))))
  (check (not (boolean? val)) #t))  ;; not #f either

;; for-each returns unspecified (can't check exact value, just no error)
(for-each (lambda (x) '()) '(1 2 3))

;; for-each side effects occur in order
(let ((result '()))
  (for-each (lambda (x) (set! result (cons x result))) '(1 2 3))
  (check result '(3 2 1)))

;; map with no lists
(check (map (lambda () 42) '()) '())

;; for-each with no lists
(for-each (lambda () '()) '())

;; map with multiple lists of different lengths
(check (map + '(1 2 3) '(4 5)) '(5 7))

;; for-each with multiple lists
(let ((sum 0))
  (for-each (lambda (a b) (set! sum (+ sum a b))) '(1 2 3) '(4 5))
  (check sum 12))

;; map with vector-map like behavior
(check (vector->list (list->vector (map (lambda (x) (* x x)) '(1 2 3))))
       '(1 4 9))

;; map with string-map like behavior
(check (map char-upcase (string->list "hello"))
       '(#\H #\E #\L #\L #\O))

;; Result
(newline)
(display "Map/for-each: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
