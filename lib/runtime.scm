(import (only (scheme base)
              or
              define
              let
              let*
              if
              >
              <
              >=
              <=
              +
              *
              -
              /
              =
              begin
              quote
              do
              when) (scheme case-lambda) (prefix (hawk sys) sys:))

(define (cons a b)
  (let ((cell (sys:ALLOC 24 3))) (sys:STORE cell a 0) (sys:STORE cell b 1) cell))
(define (not a) (if a #f #t))
(define (null? a) (sys:GUARD a 20))
(define (pair? a) (sys:GUARD a 3))
(define (boolean? a) (sys:GUARD a 4))
(define (char? a) (sys:GUARD a 12))
(define (fixnum? a) (sys:GUARD a 0))
(define (flonum? a) (sys:GUARD a 2))
(define (number? x)
  (or (fixnum? x)
     (flonum? x) ;(bignum? x) (ratnum? x) (compnum? x)
  ))
(define (procedure? a) (sys:GUARD a 5))
(define (string? a) (sys:GUARD a 9))
(define (symbol? a) (sys:GUARD a 6))
(define (vector? a) (sys:GUARD a 7))
(define (zero? z) (= z 0))
(define (negative? a) (< a 0))
(define (positive? a) (> a 0))
(define (list-tail lst k)
  (let loop ((lst lst) (k k)) (if (> k 0) (loop (cdr lst) (- k 1)) lst)))
(define (list . x) x)
(define (cdr a) (sys:LOAD a 1))
(define (car a) (sys:LOAD a 0))
(define (cadr a) (car (cdr a)))
(define (caddr a) (car (cdr (cdr a))))
(define (cddr a) (cdr (cdr a)))
(define (map f a) (if (null? a) '() (cons (f (car a)) (map f (cdr a)))))
(define (append a b) (if (null? a) b (cons (car a) (append (cdr a) b))))
(define (vector-length vec) (sys:LOAD vec 0))
;; Be careful here, we need to initialize vec before ANY other allocations
;; (including closures)
(define (vector-init vec init pos left)
  (if (= left 0)
      vec
      (begin (vector-set! vec pos init) (vector-init vec init (+ pos 1) (- left 1)))))
(define make-vector
  (case-lambda
    ((len) (make-vector len 0))
    ((len init)
      (let ((vec (sys:ALLOC (+ 16 (* len 8)) 7)))
        (sys:STORE vec len 0)
        (vector-init vec init 0 len)))))
(define (vector-ref vec idx) (sys:LOAD vec (+ 1 idx)))
(define (vector-set! vec idx val) (sys:STORE vec val (+ 1 idx)))
(define (length a)
  (let loop ((a a) (num 0)) (if (pair? a) (loop (cdr a) (+ num 1)) num)))
(define (vector->list vec)
  (let loop ((i (vector-length vec)) (l '()))
    (if (= i 0) l (loop (- i 1) (cons (vector-ref vec (- i 1)) l)))))
(define (list->vector lst)
  (let* ((len (length lst)) (v (make-vector len 0)))
    (do ((i 0 (+ i 1)) (p lst (cdr p))) ((= i len) v) (vector-set! v i (car p)))))

;; SIN
(define two-pi 6.28319)
(define pi (/ two-pi 2.0))
(define neg-pi (* -1.0 pi))
(define half-pi (/ pi 2.0))
(define neg-half-pi (* -1.0 half-pi))

(define (sin-poly x)
  ;; 9th-order odd polynomial around 0:
  ;; x - x^3/6 + x^5/120 - x^7/5040 + x^9/362880
  (let* ((x2 (* x x)) (x3 (* x2 x)) (x5 (* x3 x2)) (x7 (* x5 x2)) (x9 (* x7 x2)))
    (+ x
       (+ (* -0.166667 x3)
          (+ (* 0.00833333 x5) (+ (* -0.000198413 x7) (* 2.75573e-06 x9)))))))

(define (reduce-angle y)
  (if (> y pi)
      (reduce-angle (- y two-pi))
      (if (< y neg-pi) (reduce-angle (+ y two-pi)) y)))
(define (sin x)
  (let ((y (reduce-angle x)))
    (if (> y half-pi)
        (sin-poly (- pi y))
        (if (< y neg-half-pi) (* -1.0 (sin-poly (+ pi y))) (sin-poly y)))))


