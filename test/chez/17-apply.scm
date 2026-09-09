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

;; Basic apply
(check (apply + '(1 2 3)) 6)
(check (apply + 1 2 '(3 4)) 10)
(check (apply list '()) '())
(check (apply list '(1 2 3)) '(1 2 3))
(check (apply cons '(1 2)) '(1 . 2))

;; Apply with no arguments to proc
(check (apply + '()) 0)
(check (apply list '()) '())

;; Apply with many arguments
(let ((args (make-list 100 1)))
  (check (apply + args) 100))

;; Apply with extra arguments before tail list
(check (apply + 1 2 3 '(4 5)) 15)

;; Apply with single-element tail list
(check (apply + 1 '(2)) 3)

;; Apply with empty tail list and extra args
(check (apply + 1 2 '()) 3)

;; Apply preserves tail call semantics
(let ((result (apply (lambda args
                       (if (null? args) 'done (apply values args)))
                     '())))
  (check result 'done))

;; Apply with procedure that returns multiple values (commented out - not supported)
;; (let ((result (apply values '(1 2 3))))
;;   (call-with-values (lambda () result)
;;     (lambda (a b c) (check (+ a b c) 6))))

;; Apply with vector-like procedure
(check (apply vector '(a b c)) '#(a b c))

;; Apply with string-append
(check (apply string-append '("a" "b" "c")) "abc")
(check (apply string-append '()) "")

;; Apply error cases
(let ((ok (guard (exn (#t #t))
            (apply + 3)  ;; last arg not a list
            #f)))
  (check ok #t))

(let ((ok (guard (exn (#t #t))
            (apply + 3 4)  ;; last arg not a list
            #f)))
  (check ok #t))

(let ((ok (guard (exn (#t #t))
            (apply + '(2 3 . 4))  ;; improper list
            #f)))
  (check ok #t))

;; Result
(newline)
(display "Apply: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
