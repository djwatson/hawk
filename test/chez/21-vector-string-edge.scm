(import (scheme base) (scheme char) (scheme write))

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

;; vector-map and vector-for-each use the shortest vector and preserve order.
(check (vector-map + '#(1 2 3) '#(4 5 6)) '#(5 7 9))
(check (vector-map + '#(1 2 3) '#(4 5)) '#(5 7))
(let ((seen '()))
  (vector-for-each (lambda (x) (set! seen (cons x seen))) '#(a b c))
  (check seen '(c b a)))

;; Copy operations handle empty and sliced values.
(check (vector->list (vector-copy '#(a b c) 1 3)) '(b c))
(let ((v (vector 0 0 0 0)))
  (vector-copy! v 1 '#(a b c) 0 2)
  (check v '#(0 a b 0)))
(check (substring "abcd" 1 3) "bc")
(check (string-copy "abcd" 1 3) "bc")
(let ((s (string-copy "abcd")))
  (string-copy! s 1 "XY" 0 2)
  (check s "aXYd"))

;; TODO: Re-enable when characters support Unicode code points. Hawk currently
;; represents characters and strings as 8-bit values.
;; (check (char-ci=? (integer->char #x3c2) (integer->char #x3c3)) #t)
;; (check (char-downcase (integer->char #x3a3)) (integer->char #x3c3))
;; (check (string-foldcase "Stra\u00dfe") "strasse")
;; (check (string-ci=? "Stra\u00dfe" "STRASSE") #t)

(newline)
(display "Vector/string edge cases: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
