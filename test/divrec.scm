;;; DIVREC -- Benchmark which divides by 2 using lists of n ()'s.

(define-syntax do
       (syntax-rules ()
         ((do ((var init step ...) ...) (test expr ...) command ...)
          (let
           loop
           ((var init) ...)
           (if test
               (begin (if #f #f) expr ...)
               (begin command ... (loop (do "step" var step ...) ...)))))
         ((do "step" x) x)
         ((do "step" x y) y)))
;;; LC NOTE : Can't compute more because of heap/stack overflow

(define (create-n n)
  (do ((n n (- n 1))
       (a '() (cons '() a)))
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
(display (length (recursive-div2 (create-n 10000000))))

;0
;1
;10
;20
;50
;500
;()
;(() () () () ())
