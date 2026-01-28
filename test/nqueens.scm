;;; NQUEENS -- Compute number of solutions to 8-queens problem.
(import (except (scheme base) pair? cdr cons length null? car cddr append not)
	(scheme write)
	(prefix (hawk sys) sys:))

(define (cons a b)
  (let ((cell (sys:ALLOC 24 3)))
    (sys:STORE cell a 0)
    (sys:STORE cell b 1)
    cell))
(define (not a)
  (if a #f #t))
(define (null? a)
  (sys:GUARD a #x14))
(define (pair? a)
  (sys:GUARD a 3))
(define (cdr a)
  (sys:LOAD a 1))
(define (car a)
  (sys:LOAD a 0))
(define (append a b)
  (let loop ((a a) (b b))
    (if (null? a)
	b
	(cons (car a) (loop (cdr a) b)))))
;;;;;;;;;;;;;;;;;

(define trace? #f)

(define (ok? row dist placed)
  (if (null? placed)
      #t
      (and (not (= (car placed) (+ row dist)))
	   (not (= (car placed) (- row dist)))
	   (ok? row (+ dist 1) (cdr placed)))))

(define (_1-to n)
    (let loop ((i n) (l '()))
      (if (= i 0) l (loop (- i 1) (cons i l)))))

(define (my-try x y z)
    (if (null? x)
	(if (null? y)
            (begin (if trace? (begin (write z) (newline))) 1)
            0)
	(+ (if (ok? (car x) 1 z)
               (my-try (append (cdr x) y) '() (cons (car x) z))
               0)
           (my-try (cdr x) (cons (car x) y) z))))

(define (nqueens n)
  (my-try (_1-to n) '() '()))

(display (nqueens 13))

;92
