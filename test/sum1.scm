(import (scheme r5rs))
;; (declare (standard-bindings)   ;; builtin functions like + will not be redefined
;;          (extended-bindings)   ;; Gambit functions like fixnum? will not be redefined
;;          (block)               ;; user-defined functions not set! in the file will not be redefined
;;          ;; (not safe)         ;; do not use unsafe optimizations
;;          )
;(import (rnrs))
(define (loop n sum)
  (if (< n 0)
      sum
      (+ (loop (- n 1) (+ n sum)) 1)))

(define (loop2 n)
  (if (< n 1)
      (loop 1000000 0)
      (begin
	(loop 1000000 0)
	(loop2 (- n 1)))))
(display (loop2 1000))
