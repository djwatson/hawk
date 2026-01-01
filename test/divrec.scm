;;; DIVREC -- Benchmark which divides by 2 using lists of n ()'s.
(import (scheme base)
	(scheme r5rs)
	(prefix (hawk sys) sys:))

;;; LC NOTE : Can't compute more because of heap/stack overflow

(define (consd a b)
  (let ((cell (sys:ALLOC 24 #b001)))
    (sys:STORE cell a 0)
    (sys:STORE cell b 1)
    cell))
(define (length2 a num)
  (if (pair? a)
      (length2 (cdr a) (+ num 1))
      num))

(define (create-n n)
  (do ((n n (- n 1))
       (a '() (consd '() a)))
      ((= n 0) a)))
 
(define *ll* (create-n 200))

(define (recursive-div2 l)
  (cond ((null? l) '())
        (else (cons (car l) (recursive-div2 (cddr l))))))
  
;; (display (length (recursive-div2 (create-n 0))))
;; (display (length (recursive-div2 (create-n 2))))
;; (display (length (recursive-div2 (create-n 20))))
;; (display (length (recursive-div2 (create-n 40))))
;; (display (length (recursive-div2 (create-n 100))))

;; (display (recursive-div2 (create-n 0)))
;; (display (recursive-div2 (create-n 10)))
(display (create-n 10000) 0)
					;(display (length2 (recursive-div2 (create-n 10000000)) 0))


					;0
					;1
					;10
					;20
					;50
					;500
					;()
					;(() () () () ())
