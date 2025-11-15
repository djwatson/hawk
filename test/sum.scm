;; (declare (standard-bindings)   ;; builtin functions like + will not be redefined
;;          (extended-bindings)   ;; Gambit functions like fixnum? will not be redefined
;;          (block)               ;; user-defined functions not set! in the file will not be redefined
;;          ;; (not safe)         ;; do not use unsafe optimizations
;;          )
;(import (rnrs))
(define (loop n sum)
  (if (< n 0)
      sum
      (loop (- n 1) (+ n sum))))

(display (loop 1000000000 0))


