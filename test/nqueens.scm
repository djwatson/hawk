;;; NQUEENS -- Compute number of solutions to 8-queens problem.
(import (scheme r5rs))

;;;;;;;;;;;;;;;;;

(define trace? #f)

(define (ok? row dist placed)
  (if (null? placed)
      #t
      (and (not (= (car placed) (+ row dist)))
           (not (= (car placed) (- row dist)))
           (ok? row (+ dist 1) (cdr placed)))))

(define (_1-to n)
  (let loop ((i n) (l '())) (if (= i 0) l (loop (- i 1) (cons i l)))))

(define (my-try x y z)
  (if (null? x)
      (if (null? y) (begin (if trace? (begin (write z) (newline))) 1) 0)
      (+ (if (ok? (car x) 1 z) (my-try (append (cdr x) y) '() (cons (car x) z)) 0)
         (my-try (cdr x) (cons (car x) y) z))))

(define (nqueens n) (my-try (_1-to n) '() '()))

(define (runloop n res) (if (= n 0) res (runloop (- n 1) (nqueens 13))))
(display (runloop 10 0))

;92


