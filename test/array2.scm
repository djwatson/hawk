
(define (create-x-loop result i n)
  (if (>= i n)
      result
      (begin (vector-set! result i i) (create-x-loop result (+ i 1) n))))
(define (create-x n)
  (let ((result (make-vector n 0))) (create-x-loop result 0 n) result))

(define (create-y-loop x result i n)
  (if (< i 0)
      result
      (begin
        (vector-set! result i (vector-ref x i))
        (create-y-loop x result (- i 1) n))))

(define (create-y x)
  (let* ((n (vector-length x)) (result (make-vector n 0)))
    (create-y-loop x result (- n 1) n)))

(define (my-try n) (vector-length (create-y (create-x n))))

(define (go m n)
  (let loop ((repeat m) (result '()))
    (if (> repeat 0) (loop (- repeat 1) (my-try n)) result)))

(display (go 500 1000000))
