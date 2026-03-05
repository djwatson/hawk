;;; FFT - Fast Fourier Transform, translated from "Numerical Recipes in C"

(import (except (scheme base)
                vector-length
                make-vector
                vector-ref
                vector-set!
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
(define (make-vector len init)
  (let ((vec (sys:ALLOC (+ 16 (* len 8)) 7)))
    (sys:STORE vec len 0)
    (do ((i 0 (+ i 1))) ((= i len) vec) (vector-set! vec i init))))
(define (vector-ref vec idx) (sys:LOAD vec (+ 1 idx)))
(define (vector-set! vec idx val) (sys:STORE vec val (+ 1 idx)))
(define (length a)
  (let loop ((len 0) (a a)) (if (pair? a) (loop (+ len 1) (cdr a)) len)))
(define (vector->list vec)
  (let loop ((i (vector-length vec)) (l '()))
    (if (= i 0) l (loop (- i 1) (cons (vector-ref vec (- i 1)) l)))))

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

(define (four1 data)
  (let ((n (vector-length data)) (pi*2 6.28319)) ; to compute the inverse, negate this value

    ; bit-reversal section

    (let loop1 ((i 0) (j 0))
      (if (< i n)
          (begin
            (if (< i j)
                (begin
                  (let ((temp (vector-ref data i)))
                    (vector-set! data i (vector-ref data j))
                    (vector-set! data j temp))
                  (let ((temp (vector-ref data (+ i 1))))
                    (vector-set! data (+ i 1) (vector-ref data (+ j 1)))
                    (vector-set! data (+ j 1) temp))))
            (let loop2 ((m (quotient n 2)) (j j))
              (if (and (>= m 2) (>= j m))
                  (loop2 (quotient m 2) (- j m))
                  (loop1 (+ i 2) (+ j m)))))))

    ; Danielson-Lanczos section

    (let loop3 ((mmax 2))
      (if (< mmax n)
          (let* ((theta (/ pi*2 (exact->inexact mmax)))
                 (wpr (let ((x (sin (* 0.5 theta)))) (* -2.0 (* x x))))
                 (wpi (sin theta)))
            (let loop4 ((wr 1.0) (wi 0.0) (m 0))
              (if (< m mmax)
                  (begin
                    (let loop5 ((i m))
                      (if (< i n)
                          (let* ((j (+ i mmax))
                                 (tempr
                                    (- (* wr (vector-ref data j)) (* wi (vector-ref data (+ j 1)))))
                                 (tempi
                                    (+ (* wr (vector-ref data (+ j 1))) (* wi (vector-ref data j)))))
                            (vector-set! data j (- (vector-ref data i) tempr))
                            (vector-set! data (+ j 1) (- (vector-ref data (+ i 1)) tempi))
                            (vector-set! data i (+ (vector-ref data i) tempr))
                            (vector-set! data (+ i 1) (+ (vector-ref data (+ i 1)) tempi))
                            (loop5 (+ j mmax))) ;***))
                          (loop4 (+ (- (* wr wpr) (* wi wpi)) wr)
                                 (+ (+ (* wi wpr) (* wr wpi)) wi)
                                 (+ m 2))))))) ;******
            (loop3 (* mmax 2)))))))

(define data (make-vector 65536 0.0))

(define (run data) (four1 data) (vector-ref data 0))

(define (pp x) (display x) (display "\n"))

(define (count n res) (if (= n 0) res (count (- n 1) (run data))))
(pp (count 100 0))

;0.


