(define (this-scheme-implementation-name) (string-append "boom-" "0.1"))
;;; DERIV -- Symbolic derivation.

;;; Returns the wrong answer for quotients.
;;; Fortunately these aren't used in the benchmark.

(define (deriv a)
  (cond
    ((not (pair? a)) (if (eq? a 'x) 1 0))
    ((eq? (car a) '+) (cons '+ (map deriv (cdr a))))
    ((eq? (car a) '-) (cons '- (map deriv (cdr a))))
    ((eq? (car a) '*)
      (list '* a (cons '+ (map (lambda (a) (list '/ (deriv a) a)) (cdr a)))))
    ((eq? (car a) '/)
      (list '-
            (list '/ (deriv (cadr a)) (caddr a))
            (list '/ (cadr a) (list '* (caddr a) (caddr a) (deriv (caddr a))))))
    (else (error #f "No derivation method available"))))

(define (main)
  (let* ((count 10000000)
         (input1 '(+ (* 3 x x) (* a x x) (* b x) 5))
         (output
            '(+ (* (* 3 x x) (+ (/ 0 3) (/ 1 x) (/ 1 x)))
                (* (* a x x) (+ (/ 0 a) (/ 1 x) (/ 1 x)))
                (* (* b x) (+ (/ 0 b) (/ 1 x)))
                0))
         (s (number->string count))
         (name "deriv"))
    (run-r7rs-benchmark (string-append name ":" s)
                        count
                        (lambda () (deriv (hide count input1)))
                        (lambda (result) (equal? result output)))))

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
