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

(define-record-type point
  (make-point x y)
  point?
  (x point-x)
  (y point-y))

(define-record-type mutable-cell
  (make-cell data)
  cell?
  (data cell-value cell-set-value!))

(define-record-type empty-type
  (make-empty)
  empty?)

;; Basic predicate
(check (point? (make-point 1 2)) #t)
(check (point? 42) #f)
(check (point? "hello") #f)

;; Accessors
(let ((p (make-point 3 4)))
  (check (point-x p) 3)
  (check (point-y p) 4))

;; Multiple instances
(let ((p1 (make-point 1 2))
      (p2 (make-point 3 4)))
  (check (point-x p1) 1)
  (check (point-x p2) 3))

;; Mutators
(let ((c (make-cell 10)))
  (check (cell-value c) 10)
  (cell-set-value! c 20)
  (check (cell-value c) 20)
  (cell-set-value! c 0)
  (check (cell-value c) 0))

;; Multiple mutations
(let ((c (make-cell 1)))
  (cell-set-value! c 2)
  (cell-set-value! c 3)
  (check (cell-value c) 3))

;; Empty type
(check (empty? (make-empty)) #t)
(check (empty? 42) #f)

;; Disjoint types
(check (point? (make-cell 1)) #f)
(check (cell? (make-point 1 2)) #f)

;; Records with list fields
(define-record-type bag
  (make-bag items)
  bag?
  (items bag-items bag-set-items!))

(let ((b (make-bag '(1 2 3))))
  (check (bag-items b) '(1 2 3))
  (bag-set-items! b '())
  (check (bag-items b) '()))

;; Records with vector fields
(let ((b (make-bag (vector 1 2 3))))
  (check (vector-ref (bag-items b) 0) 1))

;; Nested records
(define-record-type line
  (make-line start end)
  line?
  (start line-start)
  (end line-end))

(let ((l (make-line (make-point 0 0) (make-point 10 20))))
  (check (point-x (line-start l)) 0)
  (check (point-y (line-end l)) 20))

;; Record equality is identity by default (not structural)
(let ((p1 (make-point 1 2))
      (p2 (make-point 1 2)))
  (check (eqv? p1 p2) #f))

;; Result
(newline)
(display "Records: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
