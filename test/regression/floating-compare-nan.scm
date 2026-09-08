; NaN is unordered: it must not satisfy any floating-point comparison.
; Keep the NaN at the end of a hot vector loop so the comparisons execute in
; JIT code after many ordinary zero comparisons.
(define v (make-vector 1000 0.0))
(vector-set! v 999 +nan.0)

(define (count-lt)
  (do ((i 0 (+ i 1)) (n 0 (if (< (vector-ref v i) 0.0) (+ n 1) n)))
      ((= i 1000) n)))

(define (count-lte)
  (do ((i 0 (+ i 1)) (n 0 (if (<= (vector-ref v i) 0.0) (+ n 1) n)))
      ((= i 1000) n)))

(define (count-eq)
  (do ((i 0 (+ i 1)) (n 0 (if (= (vector-ref v i) 0.0) (+ n 1) n)))
      ((= i 1000) n)))

(define (count-gt)
  (do ((i 0 (+ i 1)) (n 0 (if (> (vector-ref v i) 0.0) (+ n 1) n)))
      ((= i 1000) n)))

(define (count-gte)
  (do ((i 0 (+ i 1)) (n 0 (if (>= (vector-ref v i) 0.0) (+ n 1) n)))
      ((= i 1000) n)))

(display (count-lt))
(display " ")
(display (count-lte))
(display " ")
(display (count-eq))
(display " ")
(display (count-gt))
(display " ")
(display (count-gte))
(newline)

; Exercise both recorded outcomes, register operands, and self-comparisons.
(define (check pred value expected)
  (vector-fill! v value)
  (vector-set! v 999 +nan.0)
  (let ((actual
         (do ((i 0 (+ i 1))
              (n 0 (if (pred (vector-ref v i)) (+ n 1) n)))
             ((= i 1000) n))))
    (if (not (= actual expected))
        (begin (display "FAIL ") (write actual) (newline)))))

(for-each
 (lambda (value)
   (check (lambda (x) (< x 0.0)) value (if (< value 0.0) 999 0))
   (check (lambda (x) (<= x 0.0)) value (if (<= value 0.0) 999 0))
   (check (lambda (x) (= x 0.0)) value (if (= value 0.0) 999 0))
   (check (lambda (x) (> x 0.0)) value (if (> value 0.0) 999 0))
   (check (lambda (x) (>= x 0.0)) value (if (>= value 0.0) 999 0))
   (check (lambda (x) (< x x)) value 0)
   (check (lambda (x) (<= x x)) value 999)
   (check (lambda (x) (= x x)) value 999)
   (check (lambda (x) (> x x)) value 0)
   (check (lambda (x) (>= x x)) value 999))
 '(-1.0 0.0 1.0))
