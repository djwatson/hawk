(import (except (scheme base) pair? cdr cons length null? car cddr append not) (scheme write)
        (prefix (hawk sys) sys:))

(define (cons a b)
  (let ((cell (sys:ALLOC 24 3))) (sys:STORE cell a 0) (sys:STORE cell b 1) cell))
(define (not a) (if a #f #t))
(define (null? a) (sys:GUARD a 20))
(define (pair? a) (sys:GUARD a 3))
(define (cdr a) (sys:LOAD a 1))
(define (car a) (sys:LOAD a 0))

(define (listn n) (if (= n 0) '() (cons n (listn (- n 1)))))

(define l18 (listn 18))
(define l12 (listn 12))
(define l6 (listn 6))

(define (mas x y z)
  (if (not (shorterp y x))
      z
      (mas (mas (cdr x) y z) (mas (cdr y) z x) (mas (cdr z) x y))))

(define (shorterp x y)
  (and (not (null? y)) (or (null? x) (shorterp (cdr x) (cdr y)))))

(define l9 (listn 9))
(define l3 (listn 3))
(define l21 (listn 21))
(define l15 (listn 15))

(define (pp x) (display x) (display "\n"))

(pp (mas l9 l6 l3))
(pp (mas l18 l12 l6))
(pp (mas l21 l15 l9))

(pp (mas '(40 39 38 37 36 35 34 33 32 31 30 29 28 27 26 25 24 23 22 21 20 19 18 17 16 15 14 13 12 11
           10 9 8 7 6 5 4 3 2 1)
         '(20 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1)
         '(12 11 10 9 8 7 6 5 4 3 2 1)))


