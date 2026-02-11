;;; DERIV -- Symbolic derivation.

;;; Returns the wrong answer for quotients.
;;; Fortunately these aren't used in the benchmark.

(import (except (scheme base)
                map
                pair?
                cdr
                cons
                length
                null?
                car
                cadr
                caddr
                cddr
                append
                not) (scheme write) (prefix (hawk sys) sys:))

(define (cons a b)
  (let ((cell (sys:ALLOC 24 3))) (sys:STORE cell a 0) (sys:STORE cell b 1) cell))
(define (not a) (if a #f #t))
(define (null? a) (sys:GUARD a 20))
(define (pair? a) (sys:GUARD a 3))
(define (cdr a) (sys:LOAD a 1))
(define (car a) (sys:LOAD a 0))
(define (cadr a) (car (cdr a)))
(define (caddr a) (car (cdr (cdr a))))
(define (append a b) (if (null? a) b (cons (car a) (append (cdr a) b))))
(define (map f a) (if (null? a) '() (cons (f (car a)) (map f (cdr a)))))

(define (deriv a)
  (cond
    ((not (pair? a)) (if (eq? a 'x) 1 0))
    ((eq? (car a) '+) (cons '+ (map deriv (cdr a))))
    ((eq? (car a) '-) (cons '- (map deriv (cdr a))))
    ((eq? (car a) '*)
      (cons '*
            (cons a
                  (cons (cons '+ (map (lambda (a) (cons '/ (cons (deriv a) (cons a '())))) (cdr a)))
                        '()))))
    ((eq? (car a) '/)
      (cons '-
            (cons (cons '/ (cons (deriv (cadr a)) (cons (caddr a) '())))
                  (cons (cons '/
                              (cons (cadr a)
                                    (cons (cons '*
                                                (cons (caddr a)
                                                      (cons (caddr a) (cons (deriv (caddr a)) '()))))
                                          '())))
                        '()))))
    (else (error "No derivation method available"))))
(define (loop n res)
  (if (= n 0) res (loop (- n 1) (deriv '(+ (* 3 x x) (* a x x) (* b x) 5)))))

(display (loop 10000000 0))

;+**3xx+/03/1x/1x**axx+/0a/1x/1x**bx+/0b/1x0


