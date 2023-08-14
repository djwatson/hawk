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

;;  This is adapted from a benchmark written by John Ellis and Pete Kovac
;;  of Post Communications.
;;  It was modified by Hans Boehm of Silicon Graphics.
;;  It was translated into Scheme by William D Clinger of Northeastern Univ.
;;  Last modified 24 November 2007 (translated into R6RS Scheme).
;;
;;       This is no substitute for real applications.  No actual application
;;       is likely to behave in exactly this way.  However, this benchmark was
;;       designed to be more representative of real applications than other
;;       Java GC benchmarks of which we are aware.
;;       It attempts to model those properties of allocation requests that
;;       are important to current GC techniques.
;;       It is designed to be used either to obtain a single overall performance
;;       number, or to give a more detailed estimate of how collector
;;       performance varies with object lifetimes.  It prints the time
;;       required to allocate and collect balanced binary trees of various
;;       sizes.  Smaller trees result in shorter object lifetimes.  Each cycle
;;       allocates roughly the same amount of memory.
;;       Two data structures are kept around during the entire process, so
;;       that the measured performance is representative of applications
;;       that maintain some live in-memory data.  One of these is a tree
;;       containing many pointers.  The other is a large array containing
;;       double precision floating point numbers.  Both should be of comparable
;;       size.
;;
;;       The results are only really meaningful together with a specification
;;       of how much memory was used.  It is possible to trade memory for
;;       better time performance.  This benchmark should be run in a 32 MB
;;       heap, though we don't currently know how to enforce that uniformly.

;; In the Java version, this routine prints the heap size and the amount
;; of free memory.  There is no portable way to do this in Scheme; each
;; implementation needs its own version.



(define (run-benchmark2 name thunk)
  (display name)
  (newline)
  (thunk))

(define (PrintDiagnostics)
  (display " Total memory available= ???????? bytes")
  (display "  Free memory= ???????? bytes")
  (newline))

(define (gcbench kStretchTreeDepth)

  ;;  Nodes used by a tree of a given size
  (define (TreeSize i)
    (- (expt 2 (+ i 1)) 1))

  ;;  Number of iterations to use for a given tree depth
  (define (NumIters i)
    (quotient (* 2 (TreeSize kStretchTreeDepth))
              (TreeSize i)))

  ;;  Parameters are determined by kStretchTreeDepth.
  ;;  In Boehm's version the parameters were fixed as follows:
  ;;    public static final int kStretchTreeDepth    = 18;  // about 16Mb
  ;;    public static final int kLongLivedTreeDepth  = 16;  // about 4Mb
  ;;    public static final int kArraySize  = 500000;       // about 4Mb
  ;;    public static final int kMinTreeDepth = 4;
  ;;    public static final int kMaxTreeDepth = 16;
  ;;  In Larceny the storage numbers above would be 12 Mby, 3 Mby, 6 Mby.

  (let* ((kLongLivedTreeDepth (- kStretchTreeDepth 2))
         (kArraySize          (* 4 (TreeSize kLongLivedTreeDepth)))
         (kMinTreeDepth       4)
         (kMaxTreeDepth       kLongLivedTreeDepth))

    ;; Elements 3 and 4 of the allocated records are useless.
    ;; They're just to take up space, so this will be comparable
    ;; to the Java original.

    ;; (define-record-type classNode
    ;;   (make-node-raw left right i j)
    ;;   classNode?
    ;;   (left  node.left  node.left-set!)
    ;;   (right node.right node.right-set!)
    ;;   (i     node.i     node.i-set!)
    ;;   (j     node.j     node.j-set!))
    (define (make-node-raw a b c d)
      (vector a b c d))
    (define (node.left v)
      (vector-ref v 0))
    (define (node.right v)
      (vector-ref v 1))
    (define (node.left-set! v obj)
      (vector-set! v 0 obj))
    (define (node.right-set! v obj)
      (vector-set! v 1 obj))

    (let ((make-empty-node (lambda () (make-node-raw 0 0 0 0)))
	  (make-node (lambda (l r) (make-node-raw l r 0 0))))

      ;;  Build tree top down, assigning to older objects.
      (define (Populate iDepth thisNode)
        (if (<= iDepth 0)
            #f
            (let ((iDepth (- iDepth 1)))
              (node.left-set! thisNode (make-empty-node))
              (node.right-set! thisNode (make-empty-node))
              (Populate iDepth (node.left thisNode))
              (Populate iDepth (node.right thisNode)))))

      ;;  Build tree bottom-up
      (define (MakeTree iDepth)
        (if (<= iDepth 0)
            (make-empty-node)
            (make-node (MakeTree (- iDepth 1))
                       (MakeTree (- iDepth 1)))))

      (define (TimeConstruction depth)
        (let ((iNumIters (NumIters depth)))
          (display (string-append "Creating "
                                  (number->string iNumIters)
                                  " trees of depth "
                                  (number->string depth)))
          (newline)
          (run-benchmark2
           "GCBench: Top down construction"
           (lambda ()
             (do ((i 0 (+ i 1)))
                 ((>= i iNumIters))
               (Populate depth (make-empty-node)))))
          (run-benchmark2
           "GCBench: Bottom up construction"
           (lambda ()
             (do ((i 0 (+ i 1)))
                 ((>= i iNumIters))
               (MakeTree depth))))))

      (define (main)
        (display "Garbage Collector Test")
        (newline)
        (display (string-append
                  " Stretching memory with a binary tree of depth "
                  (number->string kStretchTreeDepth)))
        (newline)
        (PrintDiagnostics)
        (run-benchmark2
         "GCBench: Main"
         (lambda ()
           ;;  Stretch the memory space quickly
           (MakeTree kStretchTreeDepth)

           ;;  Create a long lived object
           (display (string-append
                     " Creating a long-lived binary tree of depth "
                     (number->string kLongLivedTreeDepth)))
           (newline)
           (let ((longLivedTree (make-empty-node)))
             (Populate kLongLivedTreeDepth longLivedTree)

             ;;  Create long-lived array, filling half of it
             (display (string-append
                       " Creating a long-lived array of "
                       (number->string kArraySize)
                       " inexact reals"))
             (newline)
             (let ((array (make-vector kArraySize 0)))
               (do ((i 0 (+ i 1)))
                   ((>= i (quotient kArraySize 2)))
                 (vector-set! array i (/ 1 (+ i 1))))
               (PrintDiagnostics)

               (do ((d kMinTreeDepth (+ d 2)))
                   ((> d kMaxTreeDepth))
                 (TimeConstruction d))

               (if (or (eq? longLivedTree '())
                       (let ((n (min 1000
                                     (- (quotient (vector-length array)
                                                  2)
                                        1))))
                         (not (= (vector-ref array n)
                                 (/ 1 (+ n 1))))))
                   (begin (display "Failed") (newline)))
               ;;  fake reference to LongLivedTree
               ;;  and array
               ;;  to keep them from being optimized away
               ))))
        (PrintDiagnostics))

      (main))))

(define (main)
  (let* ((count 1)
         (input1 20)
         (output 0)
         (s2 (number->string count))
         (s1 (number->string input1))
         (name "gcbench"))
    (display "The garbage collector should touch about ")
    (display (expt 2 (- input1 13)))
    (display " megabytes of heap storage.")
    (newline)
    (display "The use of more or less memory will skew the results.")
    (newline)
    (run-r7rs-benchmark
     (string-append name ":" s1 ":" s2)
     count
     (lambda () (gcbench (hide count input1)))
     (lambda (result) #t))))

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
