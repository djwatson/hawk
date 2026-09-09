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

;; Basic call/cc returns a value
(check (call-with-current-continuation (lambda (k) 42)) 42)

;; call/cc with explicit invocation
(check (call-with-current-continuation
         (lambda (k) (k 100)))
       100)

;; call/cc escapes from computation
(check (+ 1 (call-with-current-continuation
               (lambda (k) (+ 2 (k 10)))))
       11)

;; Nested call/cc
(check (call-with-current-continuation
         (lambda (outer)
           (call-with-current-continuation
             (lambda (inner)
               (outer (inner 42))))))
       42)

;; call/cc captured inside dynamic-wind
(let ((path '())
      (saved-k #f))
  (dynamic-wind
    (lambda () (set! path (cons 'in path)))
    (lambda ()
      (call-with-current-continuation
        (lambda (k) (set! saved-k k) 'body)))
    (lambda () (set! path (cons 'out path))))
  (check (length path) 2)
  (check (car path) 'out))

;; Result
(newline)
(display "Continuation: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
