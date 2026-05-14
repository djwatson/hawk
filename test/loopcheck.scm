;; Tests that recursive types passed to equal?, map, etc don't endlessly loop,
;; as required by r7rs.
(import (scheme base) (scheme write))
(define a (cons 'a 'b))
(set-cdr! a a)
(display a)
 (write a)
 (display (equal? a a))

(define b (cons 'a 'b))
(set-car! b b)
 (display b)
(write b)
 (display (equal? b b))

(define-syntax test-error
  (syntax-rules ()
    ((_ a)
     (let ((err (guard (cxp (#t #t)) a #f))) 
       (unless err (display "FAIL:") (display 'a) (newline))))))

(define c (cons 'a 'b))
(set-cdr! c c)
(display (equal? a c))
(newline)
(display(map cons '(1 2) '(1 2 3))) (newline)
(display (map cons '(1 2) a))
(define (triple a b c) c)
(display (map triple '(1 2) a a))
 (test-error (map triple a a a))
 (test-error (map cons a a))
(test-error (map display a))
(for-each (lambda (a b) (display a) (display ".") (display b) (newline)) '(1 2) a)
(test-error (for-each display a))
(test-error (for-each cons a a))
(test-error (for-each triple a a a))
(for-each triple a a '(1 2 3))
(for-each cons a '(1 2 3))
(test-error (length a))

(test-error (reverse a))
(test-error (apply length a))





(test-error (append a a))
(test-error (append a a a))
(test-error (append a a a a))
(test-error (append a a a a a))
 (newline)
