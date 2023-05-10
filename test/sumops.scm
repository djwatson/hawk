(define (lt a b) (< a b))
(define (sub a b) (- a b))
(define (add a b) (+ a b))

(define (loop n sum)
  (if (lt n 0)
      sum
      (loop (sub n 1) (add n sum))))

(loop 1000000000 0)
