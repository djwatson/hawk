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

;;; PUZZLE -- Forest Baskett's Puzzle benchmark, originally written in Pascal.



(define (my-iota n)
  (do ((n n (- n 1))
       (list '() (cons (- n 1) list)))
      ((zero? n) list)))

(define *size* 511)
(define classmax 3)
(define typemax 12)

(define *iii* 0)
(define *kount* 0)
(define *d* 8)

(define *piececount* (make-vector (+ classmax 1) 0))
(define *class* (make-vector (+ typemax 1) 0))
(define *piecemax* (make-vector (+ typemax 1) 0))
(define *puzzle* (make-vector (+ *size* 1)))
(define *p* (make-vector (+ typemax 1)))

(define (fit i j)
  (let ((end (vector-ref *piecemax* i)))
    (do ((k 0 (+ k 1)))
        ((or (> k end)
             (and (vector-ref (vector-ref *p* i) k)
                  (vector-ref *puzzle* (+ j k))))
         (if (> k end) #t #f)))))

(define (place i j)
  (let ((end (vector-ref *piecemax* i)))
    (do ((k 0 (+ k 1)))
        ((> k end))
      (cond ((vector-ref (vector-ref *p* i) k)
             (vector-set! *puzzle* (+ j k) #t)
             #t)))
    (vector-set! *piececount*
                 (vector-ref *class* i)
                 (- (vector-ref *piececount* (vector-ref *class* i)) 1))
    (do ((k j (+ k 1)))
        ((or (> k *size*) (not (vector-ref *puzzle* k)))
         (if (> k *size*) 0 k)))))

(define (puzzle-remove i j)
  (let ((end (vector-ref *piecemax* i)))
    (do ((k 0 (+ k 1)))
        ((> k end))
      (cond ((vector-ref (vector-ref *p* i) k)
             (vector-set! *puzzle* (+ j k) #f)
             #f)))
    (vector-set! *piececount*
                 (vector-ref *class* i)
                 (+ (vector-ref *piececount* (vector-ref *class* i)) 1))))

(define (trial j)
  (let ((k 0))
    (call-with-current-continuation
     (lambda (return)
       (do ((i 0 (+ i 1)))
           ((> i typemax) (set! *kount* (+ *kount* 1)) #f)
         (cond
          ((not
            (zero?
             (vector-ref *piececount* (vector-ref *class* i))))
           (cond
            ((fit i j)
             (set! k (place i j))
             (cond
              ((or (trial k) (zero? k))
               (set! *kount* (+ *kount* 1))
               (return #t))
              (else (puzzle-remove i j))))))))))))

(define (definePiece iclass ii jj kk)
  (let ((index 0))
    (do ((i 0 (+ i 1)))
        ((> i ii))
      (do ((j 0 (+ j 1)))
          ((> j jj))
        (do ((k 0 (+ k 1)))
            ((> k kk))
          (set! index (+ i (* *d* (+ j (* *d* k)))))
          (vector-set! (vector-ref *p* *iii*) index  #t))))
    (vector-set! *class* *iii* iclass)
    (vector-set! *piecemax* *iii* index)
    (cond ((not (= *iii* typemax))
           (set! *iii* (+ *iii* 1))))))

(define (start size)
  (set! *kount* 0)
  (do ((m 0 (+ m 1)))
      ((> m size))
    (vector-set! *puzzle* m #t))
  (do ((i 1 (+ i 1)))
      ((> i 5))
    (do ((j 1 (+ j 1)))
        ((> j 5))
      (do ((k 1 (+ k 1)))
          ((> k 5))
        (vector-set! *puzzle* (+ i (* *d* (+ j (* *d* k)))) #f))))
  (do ((i 0 (+ i 1)))
      ((> i typemax))
    (do ((m 0 (+ m 1)))
        ((> m size))
      (vector-set! (vector-ref *p* i) m #f)))
  (set! *iii* 0)
  (definePiece 0 3 1 0)
  (definePiece 0 1 0 3)
  (definePiece 0 0 3 1)
  (definePiece 0 1 3 0)
  (definePiece 0 3 0 1)
  (definePiece 0 0 1 3)

  (definePiece 1 2 0 0)
  (definePiece 1 0 2 0)
  (definePiece 1 0 0 2)

  (definePiece 2 1 1 0)
  (definePiece 2 1 0 1)
  (definePiece 2 0 1 1)

  (definePiece 3 1 1 1)

  (vector-set! *piececount* 0 13)
  (vector-set! *piececount* 1 3)
  (vector-set! *piececount* 2 1)
  (vector-set! *piececount* 3 1)
  (let ((m (+ (* *d* (+ *d* 1)) 1))
        (n 0))
    (cond ((fit 0 m) (set! n (place 0 m)))
          (else (begin (newline) (display "Error."))))
    (if (trial n)
        *kount*
        #f)))

(define (main)
  (let* ((count 1000)
         (input1 511)
         (output 2005)
         (s2 (number->string count))
         (s1 input1)
         (name "puzzle"))
    (run-r7rs-benchmark
     (string-append name ":" s2)
     count
     (lambda () (start (hide count input1)))
     (lambda (result) (equal? result output)))))

(for-each (lambda (i) (vector-set! *p* i (make-vector (+ *size* 1))))
          (my-iota (+ typemax 1)))

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
