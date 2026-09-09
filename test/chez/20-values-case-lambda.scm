(import (scheme base) (scheme case-lambda) (scheme write))

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

(define-syntax check-values
  (syntax-rules ()
    ((_ expr expected)
     (check (call-with-values (lambda () expr) list) expected))))

;; Multiple values compose through a consumer and through call/cc.
(check-values (values 2 3) '(2 3))
(check (+ 1 (call-with-values (lambda () (values 2 3)) +)) 6)
(check-values
 (call-with-values (lambda () (values 'a 'b))
   (lambda (a b) (values b a)))
 '(b a))
(check-values
 (call-with-values (lambda () (call/cc (lambda (k) (k 'a 'b))))
   (lambda args args))
 '((a b)))
(check
 (let ((f (lambda () (values 1 2 3))))
   (call-with-values f (lambda args args)))
 '(1 2 3))

;; let-values and let*-values bind all values, including rest bindings.
(check
 (let-values (((a b) (values 2 3))) (+ a b))
 5)
(check
 (let-values (((a b . rest) (values 1 2 3 4)))
   (list a b rest))
 '(1 2 (3 4)))
(check
 (let*-values (((a b) (values 2 3))
                ((c) (values (+ a b))))
   c)
 5)

;; case-lambda dispatches by arity and supports a rest clause.
(let ((f (case-lambda
           (() 'none)
           ((x) x)
           ((x y) (+ x y))
           (args (length args)))))
  (check (f) 'none)
  (check (f 7) 7)
  (check (f 2 3) 5)
  (check (f 1 2 3 4) 4))

(newline)
(display "Values/case-lambda: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
