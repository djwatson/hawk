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

;; Basic dynamic-wind
(let ((path '()))
  (dynamic-wind
    (lambda () (set! path (cons 'in path)))
    (lambda () (set! path (cons 'body path)))
    (lambda () (set! path (cons 'out path))))
  (check path '(out body in)))

;; Multiple dynamic-wind thunks
(let ((path '()))
  (dynamic-wind
    (lambda () (set! path (cons 'outer-in path)))
    (lambda ()
      (dynamic-wind
        (lambda () (set! path (cons 'inner-in path)))
        (lambda () (set! path (cons 'body path)))
        (lambda () (set! path (cons 'inner-out path)))))
    (lambda () (set! path (cons 'outer-out path))))
  (check path '(outer-out inner-out body inner-in outer-in)))

;; Dynamic-wind returns the value of the body thunk
(check (dynamic-wind (lambda () '()) (lambda () 42) (lambda () '()))
       42)

;; Dynamic-wind with call/cc
(let ((path '())
      (k #f))
  (dynamic-wind
    (lambda () (set! path (cons 'in path)))
    (lambda ()
      (call-with-current-continuation
        (lambda (c) (set! k c) 'talk1)))
    (lambda () (set! path (cons 'out path))))
  (when (< (length path) 4)
    (k 'talk2))
  (check path '(out in out in)))

;; Result
(newline)
(display "Dynamic-wind: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
