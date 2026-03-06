(import (except (scheme base)
                vector-length
                make-vector
                vector-ref
                vector-set!
                length
                vector->list
                list->vector
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
(define (list->vector lst)
  (let* ((len (length lst)) (v (make-vector len 0)))
    (do ((i 0 (+ i 1)) (p lst (cdr p))) ((= i len) v) (vector-set! v i (car p)))))

(define (quick-1 v less?)

  (define (helper left right)
    (if (< left right)
        (let ((median (my-partition v left right less?)))
          (if (< (- median left) (- right median))
              (begin (helper left (- median 1)) (helper (+ median 1) right))
              (begin (helper (+ median 1) right) (helper left (- median 1)))))
        v))

  (helper 0 (- (vector-length v) 1)))

(define (my-partition v left right less?)
  (let ((mid (vector-ref v right)))

    (define (uploop i)
      (let ((i (+ i 1)))
        (if (and (< i right) (less? (vector-ref v i) mid)) (uploop i) i)))

    (define (downloop j)
      (let ((j (- j 1)))
        (if (and (> j left) (less? mid (vector-ref v j))) (downloop j) j)))

    (define (ploop i j)
      (let* ((i (uploop i)) (j (downloop j)))
        (let ((tmp (vector-ref v i)))
          (vector-set! v i (vector-ref v j))
          (vector-set! v j tmp)
          (if (< i j)
              (ploop i j)
              (begin
                (vector-set! v j (vector-ref v i))
                (vector-set! v i (vector-ref v right))
                (vector-set! v right tmp)
                i)))))

    (ploop (- left 1) right)))

;;; Hansen's original code for this benchmark used Larceny's
;;; predefined random procedure.  When Marc Feeley modified
;;; Hansen's benchmark for the Gambit benchmark suite, however,
;;; he added a specific random number generator taken from an
;;; article in CACM.  Feeley's generator used bignums, and was
;;; extremely slow, causing the Gambit version of this benchmark
;;; to spend nearly all of its time generating the random numbers.
;;; For a benchmark called quicksort to become a bignum benchmark
;;; was very misleading, so Clinger left Feeley's version of this
;;; benchmark out of the Larceny benchmark suite.
;;;
;;; The following random number generator is much better and
;;; faster than the one used in the Gambit benchmark.  See
;;;
;;; http://srfi.schemers.org/srfi-27/mail-archive/msg00000.html
;;; http://www.math.purdue.edu/~lucier/random/random.scm

;;; A uniform [0,1] random number generator; is
;;; Pierre L'Ecuyer's generator from his paper
;;; "Good parameters and implementations for combined multiple
;;; recursive random number generators"
;;; available at his web site http://www.iro.umontreal.ca/~lecuyer

(define seed-set! #f)
(define seed-ref #f)
(define random-flonum #f)

(let ((norm 2.32831e-10)
      (m1 4.29497e+09)
      (m2 4.29494e+09)
      (a12 1.40358e+06)
      (a13n 810728.0)
      (a21 527612.0)
      (a23n 1.37059e+06)
      (seed (list->vector (vector->list '#(1.0 0.0 0.0 1.0 0.0 0.0))))) ;; will be mutated

  ;; uses no conversions between flonums and fixnums.

  (set! random-flonum
    (lambda ()
      (let ((seed seed)) ;; make it local
        (let ((p1 (- (* a12 (vector-ref seed 1)) (* a13n (vector-ref seed 0))))
              (p2 (- (* a21 (vector-ref seed 5)) (* a23n (vector-ref seed 3)))))
          (let ((k1 (truncate (/ p1 m1)))
                (k2 (truncate (/ p2 m2)))
                (ignore1 (vector-set! seed 0 (vector-ref seed 1)))
                (ignore3 (vector-set! seed 3 (vector-ref seed 4))))
            (let ((p1 (- p1 (* k1 m1)))
                  (p2 (- p2 (* k2 m2)))
                  (ignore2 (vector-set! seed 1 (vector-ref seed 2)))
                  (ignore4 (vector-set! seed 4 (vector-ref seed 5))))
              (let ((p1 (if (< p1 0.0) (+ p1 m1) p1)) (p2 (if (< p2 0.0) (+ p2 m2) p2)))
                (vector-set! seed 2 p1)
                (vector-set! seed 5 p2)
                (if (<= p1 p2) (* norm (+ (- p1 p2) m1)) (* norm (- p1 p2))))))))))

  (set! seed-ref (lambda () (vector->list seed)))

  (set! seed-set! (lambda l (set! seed (list->vector l)))))

(define (random n) (exact (truncate (* (inexact n) (random-flonum)))))

;;; Even with the improved random number generator,
;;; this benchmark still spends almost all of its time
;;; generating the random vector.  To make this a true
;;; quicksort benchmark, we generate a relatively small
;;; random vector and then sort many copies of it.

(define n 10000)
(define v (make-vector n 0))
(define r 1000000)
(do ((i 0 (+ i 1))) ((= i n)) (vector-set! v i (random r)))
(define (main n res)
  (if (= n 0)
      res
      (main (- n 1)
            (quick-1 (list->vector (vector->list v)) (lambda (x y) (< x y))))))

;; 2500
(main 2500 0)

