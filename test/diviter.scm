(import (except (scheme base) pair? cdr cons length null? car cddr) (scheme write)
        (prefix (hawk sys) sys:))

(define (cons a b)
  (let ((cell (sys:ALLOC 24 3))) (sys:STORE cell a 0) (sys:STORE cell b 1) cell))
(define (pair? a) (sys:GUARD a 3))
(define (null? a) (sys:GUARD a 20))
(define (length a)
  (let loop ((a a) (num 0)) (if (pair? a) (loop (cdr a) (+ num 1)) num)))
(define (cdr a) (sys:LOAD a 1))
(define (car a) (sys:LOAD a 0))
(define (cddr a) (cdr (cdr a)))

;;;

(define (create-n n) (do ((n n (- n 1)) (a '() (cons '() a))) ((= n 0) a)))

(define (iterative-div2 l)
  (do ((l l (cddr l)) (a '() (cons (car l) a))) ((null? l) a)))

(define (run x ll out)
  (if (= x 0) out (run (- x 1) ll (iterative-div2 ll))))

(let ((ll (create-n 1000)))
  (display (length (run 1000000 ll 0))))

