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

;;; MBROT -- Generation of Mandelbrot set fractal
;;; using Scheme's complex numbers.



(define (count z0 step z)

  (let* ((max-count 64)
         (radius    4.0)
         (radius^2  (* radius radius)))

    (let ((z0 (+ z0 (* z step))))

      (let loop ((z z0)
                 (c 0))
        (if (= c max-count)
            c
            (let* ((zr (real-part z))
                   (zi (imag-part z))
                   (zr^2 (* zr zr))
                   (zi^2 (* zi zi)))
              (if (> (+ zr^2 zi^2) radius^2)
                  c
                  (loop (+ (* z z) z0) (+ c 1)))))))))

(define (mbrot matrix z0 step n)
  (let loop1 ((y (- n 1)))
    (when (>= y 0)
        (let loop2 ((x (- n 1)))
          (if (>= x 0)
            (begin
              (vector-set! (vector-ref matrix x)
                            y
                            (count z0
                                   step
                                   (make-rectangular (inexact x)
                                                     (inexact y))))
              (loop2 (- x 1)))
            (loop1 (- y 1)))))))

(define (test n)
  (let ((matrix (make-vector n)))
    (let loop ((i (- n 1)))
      (when (>= i 0)
        (vector-set! matrix i (make-vector n))
        (loop (- i 1))))
    (mbrot matrix -1.0-0.5i 0.005 n)
    (vector-ref (vector-ref matrix 0) 0)))

(define (main)
  (let* ((count 1000)
         (input1 75)
         (output 5)
         (s2 (number->string count))
         (s1 (number->string input1))
         (name "mbrotZ"))
    (run-r7rs-benchmark
     (string-append name ":" s1 ":" s2)
     count
     (lambda () (test (hide count input1)))
     (lambda (result) (= result output)))))

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
