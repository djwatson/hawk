(define (this-scheme-implementation-name)
  (string-append "boom-" "0.1"))
(define (inexact a) (exact->inexact a))
(define (inexact->exact a) a)
(define (exact a) (inexact->exact a))
(define (square n) (* n n))
(define (jiffies-per-second)
  1000000000 ;; returns 1 on my Bones, which is wrong. this number should work for ?many? linuxen
  )
;; vector-map
;; read-line
;; complex/rational functions
;; define-record-type
(define-syntax import
  (syntax-rules ()
    ((import stuff ...)
     (begin) ;; do nothing
     )))
(define-syntax when
  (syntax-rules ()
    ((when a b c ...)
     (if a (begin b c ...)))))
(define-syntax unless
  (syntax-rules ()
    ((unless a b c ...)
     (if (not a) (begin b c ...)))))
(define (jiffies-per-second) 1)
;;(define (current-jiffy) (with-input-from-file "/proc/uptime" read))
;;(define (current-second) (with-input-from-file "/proc/uptime" read))
(define (current-jiffy) 0)
(define (current-second) 0)

;;; FFT - Fast Fourier Transform, translated from "Numerical Recipes in C"


;;; We need R6RS div for this benchmark.

(define (div x y)
  (cond ((and (exact-integer? x)
              (exact-integer? y)
              (>= x 0))
         (quotient x y))
        ((< y 0)
         ;; x < 0, y < 0
         (let* ((q (quotient x y))
                (r (- x (* q y))))
           (if (= r 0)
               q
               (+ q 1))))
        (else
         ;; x < 0, y > 0
         (let* ((q (quotient x y))
                (r (- x (* q y))))
           (if (= r 0)
               q
               (- q 1))))))

;;(define sin sin)

(define (four1 data)
  (let ((n (vector-length data))
        (pi*2 6.28318530717959)) ; to compute the inverse, negate this value

    ;; bit-reversal section

    (let loop1 ((i 0) (j 0))
      (when (< i n)
        (when (< i j)
          (let ((temp (vector-ref data i)))
            (vector-set! data i (vector-ref data j))
            (vector-set! data j temp))
          (let ((temp (vector-ref data (+ i 1))))
            (vector-set! data (+ i 1) (vector-ref data (+ j 1)))
            (vector-set! data (+ j 1) temp)))
        (let loop2 ((m (div n 2)) (j j))
          (if (and (>= m 2) (>= j m))
            (loop2 (div m 2) (- j m))
            (loop1 (+ i 2) (+ j m))))))

    ;; Danielson-Lanczos section

    (let loop3 ((mmax 2))
      (when (< mmax n)
        (let* ((theta
                (/ pi*2 (inexact mmax)))
               (wpr
                (let ((x (sin (* 0.5 theta))))
                  (* -2.0 (* x x))))
               (wpi
                (sin theta)))
          (let loop4 ((wr 1.0) (wi 0.0) (m 0))
            (when (< m mmax)
              (let loop5 ((i m))
                (if (< i n)
                  (let* ((j
                          (+ i mmax))
                         (tempr
                          (-
                            (* wr (vector-ref data j))
                            (* wi (vector-ref data (+ j 1)))))
                         (tempi
                          (+
                            (* wr (vector-ref data (+ j 1)))
                            (* wi (vector-ref data j)))))
                    (vector-set! data j
                      (- (vector-ref data i) tempr))
                    (vector-set! data (+ j 1)
                      (- (vector-ref data (+ i 1)) tempi))
                    (vector-set! data i
                      (+ (vector-ref data i) tempr))
                    (vector-set! data (+ i 1)
                      (+ (vector-ref data (+ i 1)) tempi))
                    (loop5 (+ j mmax)));***))
              (loop4 (+ (- (* wr wpr) (* wi wpi)) wr)
                     (+ (+ (* wi wpr) (* wr wpi)) wi)
                     (+ m 2))))
          ));******
          (loop3 (* mmax 2)))))))

(define data
  (make-vector 1024 0.0))

(define (run data)
  (four1 data)
  (vector-ref data 0))

(define (main)
  (let* ((count 100)
         (input1 65536)
         (input2 0.0)
         (output 0.0)
         (s2 (number->string count))
         (s1 (number->string input1))
         (name "fft"))
    (run-r7rs-benchmark
     (string-append name ":" s1 ":" s2)
     count
     (lambda ()
       (run (hide count (make-vector input1 input2))))
     (lambda (result) (equal? result output)))))

;;; The following code is appended to all benchmarks.

;;; Given an integer and an object, returns the object
;;; without making it too easy for compilers to tell
;;; the object will be returned.

(define (hide r x)
  (call-with-values
   (lambda ()
     (values (vector values (lambda (x) x))
             (if (< r 100) 0 1)))
   (lambda (v i)
     ((vector-ref v i) x))))

;;; Given the name of a benchmark,
;;; the number of times it should be executed,
;;; a thunk that runs the benchmark once,
;;; and a unary predicate that is true of the
;;; correct results the thunk may return,
;;; runs the benchmark for the number of specified iterations.

(define (run-r7rs-benchmark name count thunk ok?)

  ;; Rounds to thousandths.
  (define (rounded x)
    (/ (round (* 1000 x)) 1000))

  (display "Running ")
  (display name)
  (newline)
  (flush-output-port (current-output-port))
  (let* ((j/s (jiffies-per-second))
         (t0 (current-second))
         (j0 (current-jiffy)))
    (let loop ((i 0)
               (result #f))
      (cond ((< i count)
             (loop (+ i 1) (thunk)))
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
