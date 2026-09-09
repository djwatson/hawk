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

(define (cycle3 a b c)
  (let ((x (list a b c)))
    (set-cdr! (cddr x) x)
    x))

(define (cycle6 a b c)
  (let ((x (list a b c a b c)))
    (set-cdr! (list-tail x 5) x)
    x))

;; Equal cyclic lists may have different finite representations.
(check (equal? (cycle3 'a 'b 'c) (cycle3 'a 'b 'c)) #t)
(check (equal? (cycle3 'a 'b 'c) (cycle6 'a 'b 'c)) #t)
(check (equal? (cycle3 'a 'b 'c) (cycle3 'a 'b 'd)) #f)

;; Cyclic vectors terminate and compare their contents.
(let ((a (vector 'x #f))
      (b (vector 'x #f)))
  (vector-set! a 1 a)
  (vector-set! b 1 b)
  (check (equal? a b) #t)
  (vector-set! b 0 'y)
  (check (equal? a b) #f))

;; Pair and vector cycles remain distinct shapes when their data differs.
(let ((a (vector #f))
      (b (vector #f)))
  (vector-set! a 0 a)
  (vector-set! b 0 (vector b))
  (check (equal? a b) #t)
  (vector-set! b 0 (vector 'different))
  (check (equal? a b) #f))

;; Deep shared DAGs exercise the graph-aware slow path without expanding trees.
(define (shared-tree depth leaf)
  (if (= depth 0)
      leaf
      (let ((child (shared-tree (- depth 1) leaf)))
        (cons child child))))

(let ((a (shared-tree 300 '(leaf)))
      (b (shared-tree 300 '(leaf)))
      (c (shared-tree 300 '(other))))
  (check (equal? a b) #t)
  (check (equal? a c) #f)
  (check (equal? a a) #t))

;; Scalar and aggregate exactness follows eqv? at the leaves.
(check (equal? 3 3.0) #f)
(check (equal? '#(1 2 #(3 4)) '#(1 2 #(3 4))) #t)
(check (equal? '#u8(1 2 3) '#u8(1 2 3)) #t)
(check (equal? '#u8(1 2 3) '#u8(1 2 4)) #f)

(newline)
(display "Equal graphs: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
