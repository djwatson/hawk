;;; DERIV -- Symbolic derivation.

;;; Returns the wrong answer for quotients.
;;; Fortunately these aren't used in the benchmark.
(import (scheme r5rs) (scheme base))

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


