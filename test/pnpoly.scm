(import (except (scheme base)
                vector-length
                make-vector
                vector-ref
                vector-set!
                list->vector
                length
                vector->list
                cons
                car
                cdr
                pair?
                not) (only (scheme r5rs) exact->inexact) (scheme write) (prefix (hawk sys) sys:))

(define (cons a b)
  (let ((cell (sys:ALLOC 24 3))) (sys:STORE cell a 0) (sys:STORE cell b 1) cell))

(define (cdr a) (sys:LOAD a 1))
(define (car a) (sys:LOAD a 0))

(define (not a) (if a #f #t))
(define (pair? a) (sys:GUARD a 3))
(define (vector-length vec) (sys:LOAD vec 0))
(define (make-vector len)
  (let ((vec (sys:ALLOC (+ 16 (* len 8)) 7))) (sys:STORE vec len 0) vec))
(define (vector-ref vec idx) (sys:LOAD vec (+ 1 idx)))
(define (vector-set! vec idx val) (sys:STORE vec val (+ 1 idx)))
(define (list->vector lst)
  (let* ((len (length lst)) (v (make-vector len)))
    (do ((i 0 (+ i 1)) (p lst (cdr p))) ((= i len) v) (vector-set! v i (car p)))))
(define (length a)
  (let loop ((len 0) (a a)) (if (pair? a) (loop (+ len 1) (cdr a)) len)))
(define (vector->list vec)
  (let loop ((i (vector-length vec)) (l '()))
    (if (= i 0) l (loop (- i 1) (cons (vector-ref vec (- i 1)) l)))))

(define (pt-in-poly2 xp yp x y)
  (let loop ((c #f) (i (- (vector-length xp) 1)) (j 0))
    (if (< i 0)
        c
        (if (or (and (or (> (vector-ref yp i) y) (>= y (vector-ref yp j)))
                     (or (> (vector-ref yp j) y) (>= y (vector-ref yp i))))
               (>= x
                   (+ (vector-ref xp i)
                      (/ (* (- (vector-ref xp j) (vector-ref xp i)) (- y (vector-ref yp i)))
                         (- (vector-ref yp j) (vector-ref yp i))))))
            (loop c (- i 1) i)
            (loop (not c) (- i 1) i)))))

(define (run input1 input2)
  (let ((count 0)
        (xp (list->vector (vector->list input1)))
        (yp (list->vector (vector->list input2))))
    (when (pt-in-poly2 xp yp 0.5 0.5) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp 0.5 1.5) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp -0.5 1.5) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp 0.75 2.25) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp 0.0 2.01) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp -0.5 2.5) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp -1.0 -0.5) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp -1.5 0.5) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp -2.25 -1.0) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp 0.5 -0.25) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp 0.5 -1.25) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp -0.5 -2.5) (set! count (+ count 1)))
    count))

(define (do-run n res)
  (if (= n 0)
      res
      (do-run (- n 1)
              (run '#(0.0 1.0 1.0 0.0 0.0 1.0 -0.5 -1.0 -1.0 -2.0 -2.5 -2.0 -1.5 -0.5 1.0 1.0 0.0
                      -0.5 -1.0 -0.5)
                   '#(0.0 0.0 1.0 1.0 2.0 3.0 2.0 3.0 0.0 -0.5 -1.0 -1.5 -2.0 -2.0 -1.5 -1.0 -0.5
                      -1.0 -1.0 -0.5)))))

(display (do-run 1000000 0))
