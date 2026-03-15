(import (scheme r5rs))

(define (create-n n) (do ((n n (- n 1)) (a '() (cons '() a))) ((= n 0) a)))

(define (recursive-div2 l)
  (cond ((null? l) '()) (else (cons (car l) (recursive-div2 (cddr l))))))

;; (display (length (recursive-div2 (create-n 0))))

;; (display (length (recursive-div2 (create-n 2))))

;; (display (length (recursive-div2 (create-n 20))))

;;(display (length (recursive-div2 (create-n 40))))

;; (display (length (recursive-div2 (create-n 100))))

;; (display (recursive-div2 (create-n 0)))
;; (display (recursive-div2 (create-n 10)))

(define (run x ll out) (if (= x 0) out (run (- x 1) ll (recursive-div2 ll))))
;(display (length (recursive-div2 (create-n 1000))))
(let ((ll (create-n 1000))) (display (length (run 1000000 ll 0))))


