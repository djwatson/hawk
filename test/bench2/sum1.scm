(define (this-scheme-implementation-name) (string-append "boom-" "0.1"))

;;; SUM1 -- One of the Kernighan and Van Wyk benchmarks.

(define (sumport port sum-so-far)
  (let ((x (read port)))
    (if (eof-object? x) sum-so-far (sumport port (+ x sum-so-far)))))

(define (sum port) (sumport port 0.0))

(define (go input) (call-with-input-file input sum))

(define (main)
  (let* ((count 25)
         (input1 "inputs/sum1.data")
         (output 15795.0)
         (s2 (number->string count))
         (s1 input1)
         (name "sum1"))
    (run-r7rs-benchmark (string-append name ":" s2)
                        count
                        (lambda () (go (hide count input1)))
                        (lambda (result) (<= (abs (- result output)) 1e-09)))))

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
