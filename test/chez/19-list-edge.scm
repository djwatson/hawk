(import (scheme base) (scheme cxr) (scheme write))

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

(define (raises? thunk)
  (guard (exn (#t #t))
    (thunk)
    #f))

(define (cyclic-list)
  (let ((x (list 'a 'b 'c)))
    (set-cdr! (cddr x) x)
    x))

;; list-tail preserves the original list cells.
(let ((x (list 'a 'b 'c)))
  (check (eq? (list-tail x 0) x) #t)
  (check (eq? (list-tail x 2) (cddr x)) #t)
  (check (null? (list-tail x 3)) #t))

;; list-ref and list-tail reject invalid positions.
(check (raises? (lambda () (list-ref '(a b c) -1))) #t)
(check (raises? (lambda () (list-ref '(a b c) 3))) #t)
(check (raises? (lambda () (list-tail '(a b c) -1))) #t)
(check (raises? (lambda () (list-tail '(a b . c) 3))) #t)

;; Operations requiring proper finite lists reject improper and cyclic lists.
(check (raises? (lambda () (list-copy '(a b . c)))) #t)
(check (raises? (lambda () (list-copy (cyclic-list)))) #t)
(check (raises? (lambda () (append '(a b . c) '()))) #t)
(check (raises? (lambda () (append (cyclic-list) '()))) #t)
(check (raises? (lambda () (reverse '(a b . c)))) #t)
(check (raises? (lambda () (reverse (cyclic-list)))) #t)

;; Association and membership procedures return the matching tail or pair.
(let ((x '((a 1) (b 2) (c 3))))
  (check (eq? (assq 'b x) (cadr x)) #t)
  (check (eq? (assv 'c x) (caddr x)) #t)
  (check (eq? (assoc 'a x) (car x)) #t)
  (check (member '(b 2) x) '((b 2) (c 3))))

(newline)
(display "List edge cases: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
