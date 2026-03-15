(import (scheme r5rs))

(define (pt-in-poly2 xp yp x y)
  (let loop ((c #f) (i (- (vector-length xp) 1)) (j 0))
    (if (< i 0)
        c
        (if (or (and (or (> (vector-ref yp i) y) (>= y (vector-ref yp j)))
                     (or (> (vector-ref yp j) y) (>= y (vector-ref yp i))))
               (>= x
                   (+ (vector-ref xp i)
                      (/ (* (- (vector-ref xp j) (vector-ref xp i)) (- y (vector-ref yp i)))
                         (- (vector-ref yp j) (vector-ref yp i))))))
            (loop c (- i 1) i)
            (loop (not c) (- i 1) i)))))

(define (run input1 input2)
  (let ((count 0)
        (xp (list->vector (vector->list input1)))
        (yp (list->vector (vector->list input2))))
    (when (pt-in-poly2 xp yp 0.5 0.5) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp 0.5 1.5) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp -0.5 1.5) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp 0.75 2.25) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp 0.0 2.01) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp -0.5 2.5) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp -1.0 -0.5) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp -1.5 0.5) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp -2.25 -1.0) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp 0.5 -0.25) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp 0.5 -1.25) (set! count (+ count 1)))
    (when (pt-in-poly2 xp yp -0.5 -2.5) (set! count (+ count 1)))
    count))

(define (do-run n res)
  (if (= n 0)
      res
      (do-run (- n 1)
              (run '#(0.0 1.0 1.0 0.0 0.0 1.0 -0.5 -1.0 -1.0 -2.0 -2.5 -2.0 -1.5 -0.5 1.0 1.0 0.0
                      -0.5 -1.0 -0.5)
                   '#(0.0 0.0 1.0 1.0 2.0 3.0 2.0 3.0 0.0 -0.5 -1.0 -1.5 -2.0 -2.0 -1.5 -1.0 -0.5
                      -1.0 -1.0 -0.5)))))

(display (do-run 1000000 0))
