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

;;; DESTRUC -- Destructive operation benchmark.



(define (append-to-tail! x y)
  (if (null? x)
      y
      (let loop ((a x) (b (cdr x)))
        (if (null? b)
            (begin
              (set-cdr! a y)
              x)
            (loop b (cdr b))))))

(define (destructive n m)
  (let ((l (do ((i 10 (- i 1)) (a '() (cons '() a)))
               ((= i 0) a))))
    (do ((i n (- i 1)))
        ((= i 0) l)
      (cond ((null? (car l))
             (do ((l l (cdr l)))
                 ((null? l))
               (when (null? (car l))
                 (set-car! l (cons '() '())))
               (append-to-tail! (car l)
                                (do ((j m (- j 1)) (a '() (cons '() a)))
                                    ((= j 0) a)))))
            (else
             (do ((l1 l (cdr l1)) (l2 (cdr l) (cdr l2)))
                 ((null? l2))
               (set-cdr! (do ((j (quotient (length (car l2)) 2) (- j 1))
                              (a (car l2) (cdr a)))
                             ((zero? j) a)
                           (set-car! a i))
                         (let ((n (quotient (length (car l1)) 2)))
                           (cond ((= n 0)
                                  (set-car! l1 '())
                                  (car l1))
                                 (else
                                  (do ((j n (- j 1)) (a (car l1) (cdr a)))
                                      ((= j 1)
                                       (let ((x (cdr a)))
                                         (set-cdr! a '())
                                         x))
                                    (set-car! a i))))))))))))

(define (main)
  (let* ((count 4000)
         (input1 600)
         (input2 50)
         (output '((1 1 2)
 (1 1 1)
 (1 1 1 2)
 (1 1 1 1)
 (1 1 1 1 2)
 (1 1 1 1 2)
 (1 1 1 1 2)
 (1 1 1 1 2)
 (1 1 1 1 2)
 (1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 3)))
         (s3 (number->string count))
         (s2 (number->string input2))
         (s1 (number->string input1))
         (name "destruc"))
    (run-r7rs-benchmark
     (string-append name ":" s1 ":" s2 ":" s3)
     count
     (lambda ()
       (destructive (hide count input1) (hide count input2)))
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
