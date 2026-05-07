(define (this-scheme-implementation-name) (string-append "boom-" "0.1"))

;;; PNPOLY - Test if a point is contained in a 2D polygon.

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

(define (main)
  (let* ((count 1000000)
         (input1
            '#(0.0 1.0 1.0 0.0 0.0 1.0 -0.5 -1.0 -1.0 -2.0 -2.5 -2.0 -1.5 -0.5 1.0 1.0 0.0 -0.5 -1.0
               -0.5))
         (input2
            '#(0.0 0.0 1.0 1.0 2.0 3.0 2.0 3.0 0.0 -0.5 -1.0 -1.5 -2.0 -2.0 -1.5 -1.0 -0.5 -1.0 -1.0
               -0.5))
         (output 6)
         (s2 (number->string count))
         (s1 "")
         (name "pnpoly"))
    (run-r7rs-benchmark (string-append name ":" s2)
                        count
                        (lambda () (run (hide count input1) (hide count input2)))
                        (lambda (result) (and (number? result) (= result output))))))

;;; The following code is appended to all benchmarks.

;;; Given an integer and an object, returns the object
;;; without making it too easy for compilers to tell
;;; the object will be returned.

(define (hide r x)
  (call-with-values (lambda () (values (vector values (lambda (x) x)) (if (< r 100) 0 1)))
                    (lambda (v i) ((vector-ref v i) x))))

;;; Given the name of a benchmark,
;;; the number of times it should be executed,
;;; a thunk that runs the benchmark once,
;;; and a unary predicate that is true of the
;;; correct results the thunk may return,
;;; runs the benchmark for the number of specified iterations.

(define (run-r7rs-benchmark name count thunk ok?)

  ;; Rounds to thousandths.
  (define (rounded x) (/ (round (* 1000 x)) 1000))

  (display "Running ")
  (display name)
  (newline)
  (flush-output-port (current-output-port))
  (let* ((j/s (jiffies-per-second)) (t0 (current-second)) (j0 (current-jiffy)))
    (let loop ((i 0) (result #f))
      (cond
        ((< i count) (loop (+ i 1) (thunk)))
        ((ok? result)
          (let* ((j1 (current-jiffy))
                 (t1 (current-second))
                 (jifs (- j1 j0))
                 (secs (inexact (/ jifs j/s)))
                 (secs2 (rounded (- t1 t0))))
            (display "Elapsed time: ")
            (write secs)
            (display " seconds (")
            (write secs2)
            (display ") for ")
            (display name)
            (newline)
            (display "+!CSVLINE!+")
            (display (this-scheme-implementation-name))
            (display ",")
            (display name)
            (display ",")
            (display secs)
            (newline)
            (flush-output-port (current-output-port)))
          result)
        (else
          (display "ERROR: returned incorrect result: ")
          (write result)
          (newline)
          (flush-output-port (current-output-port))
          result)))))
(main)
