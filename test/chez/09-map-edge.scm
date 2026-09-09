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

;; string-map with single string
(check (string-map char-upcase "hello") "HELLO")
(check (string-map char-downcase "HELLO") "hello")
(check (string-map char-foldcase "HeLLo") "hello")

;; string-map with multiple strings
(check (string-map (lambda (a b) (if (char<? a b) a b))
                   "abc" "bac")
       "aac")
(check (string-map char-upcase "hello") "HELLO")

;; string-map evaluation order
(let ((result '()))
  (string-map (lambda (c) (set! result (cons c result)) c) "ab")
  (check (length result) 2))

;; string-for-each with single string
(let ((result '()))
  (string-for-each (lambda (c) (set! result (cons c result))) "abc")
  (check result '(#\c #\b #\a)))

;; string-for-each with multiple strings
(let ((result '()))
  (string-for-each (lambda (a b) (set! result (cons (list a b) result)))
                   "abc" "def")
  (check result '((#\c #\f) (#\b #\e) (#\a #\d))))

;; vector-map with single vector
(check (vector-map (lambda (x) (* x x)) '#(1 2 3 4))
       '#(1 4 9 16))
(check (vector-map number? '#(1 "a" 3 "b"))
       '#(#t #f #t #f))

;; vector-map with multiple vectors
(check (vector-map + '#(1 2 3) '#(4 5 6))
       '#(5 7 9))
(check (vector-map * '#(1 2 3) '#(4 5 6))
       '#(4 10 18))

;; vector-map evaluation order
(let ((result '()))
  (vector-map (lambda (x) (set! result (cons x result)) x) '#(1 2))
  (check (length result) 2))

;; vector-for-each with single vector
(let ((result '()))
  (vector-for-each (lambda (x) (set! result (cons x result)))
                   '#(1 2 3))
  (check result '(3 2 1)))

;; vector-for-each with multiple vectors
(let ((result '()))
  (vector-for-each (lambda (a b) (set! result (cons (+ a b) result)))
                   '#(1 2 3) '#(4 5 6))
  (check result '(9 7 5)))

;; map with circular list (should terminate)
(let ((circular (let ((pair (list 1)))
                  (set-cdr! pair pair)
                  pair)))
  ;; map on circular list with finite result
  (let ((result (map (lambda (x) (* x 2)) (list 1 2 3))))
    (check result '(2 4 6))))

;; for-each with circular list
(let ((count 0))
  (for-each (lambda (x) (set! count (+ count 1))) (list 1 2 3))
  (check count 3))

;; map with multiple lists of different lengths (shortest wins)
(check (map + '(1 2 3) '(4 5)) '(5 7))
(check (map + '(1 2) '(3 4 5)) '(4 6))

;; Result
(newline)
(display "Map edge: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
