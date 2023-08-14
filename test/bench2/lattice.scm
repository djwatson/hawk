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

;;; LATTICE -- Obtained from Andrew Wright.



;; Given a comparison routine that returns one of
;;       less
;;       more
;;       equal
;;       uncomparable
;; return a new comparison routine that applies to sequences.
(define lexico
  (lambda (base)
    (define lex-fixed
      (lambda (fixed lhs rhs)
        (define check
          (lambda (lhs rhs)
            (if (null? lhs)
                fixed
                (let ((probe
                       (base (car lhs)
                             (car rhs))))
                  (if (or (eq? probe 'equal)
                          (eq? probe fixed))
                      (check (cdr lhs)
                             (cdr rhs))
                      'uncomparable)))))
        (check lhs rhs)))
    (define lex-first
      (lambda (lhs rhs)
        (if (null? lhs)
            'equal
            (let ((probe
                   (base (car lhs)
                         (car rhs))))
              (case probe
                ((less more)
                 (lex-fixed probe
                            (cdr lhs)
                            (cdr rhs)))
                ((equal)
                 (lex-first (cdr lhs)
                            (cdr rhs)))
                ((uncomparable)
                 'uncomparable))))))
    lex-first))

(define (make-lattice elem-list cmp-func)
  (cons elem-list cmp-func))

(define lattice->elements car)

(define lattice->cmp cdr)

;; Select elements of a list which pass some test.
(define zulu-select
  (lambda (test lst)
    (define select-a
      (lambda (ac lst)
        (if (null? lst)
            (xreverse! ac)
            (select-a
             (let ((head (car lst)))
               (if (test head)
                   (cons head ac)
                   ac))
             (cdr lst)))))
    (select-a '() lst)))

(define xreverse!
  (letrec ((rotate
            (lambda (fo fum)
              (let ((next (cdr fo)))
                (set-cdr! fo fum)
                (if (null? next)
                    fo
                    (rotate next fo))))))
    (lambda (lst)
      (if (null? lst)
          '()
          (rotate lst '())))))

;; Select elements of a list which pass some test and map a function
;; over the result.  Note, only efficiency prevents this from being the
;; composition of select and map.
(define select-map
  (lambda (test func lst)
    (define select-a
      (lambda (ac lst)
        (if (null? lst)
            (xreverse! ac)
            (select-a
             (let ((head (car lst)))
               (if (test head)
                   (cons (func head)
                         ac)
                   ac))
             (cdr lst)))))
    (select-a '() lst)))



;; This version of map-and tail-recurses on the last test.
(define map-and
  (lambda (proc lst)
    (if (null? lst)
        #t
        (letrec ((drudge
                  (lambda (lst)
                    (let ((rest (cdr lst)))
                      (if (null? rest)
                          (proc (car lst))
                          (and (proc (car lst))
                               (drudge rest)))))))
          (drudge lst)))))

(define (maps-1 source target pas new)
  (let ((scmp (lattice->cmp source))
        (tcmp (lattice->cmp target)))
    (let ((less
           (select-map
            (lambda (p)
              (eq? 'less
                   (scmp (car p) new)))
            cdr
            pas))
          (more
           (select-map
            (lambda (p)
              (eq? 'more
                   (scmp (car p) new)))
            cdr
            pas)))
      (zulu-select
       (lambda (t)
         (and
          (map-and
           (lambda (t2)
             (memq (tcmp t2 t) '(less equal)))
           less)
          (map-and
           (lambda (t2)
             (memq (tcmp t2 t) '(more equal)))
           more)))
       (lattice->elements target)))))

(define (maps-rest source target pas rest to-1 to-collect)
  (if (null? rest)
      (to-1 pas)
      (let ((next (car rest))
            (rest (cdr rest)))
        (to-collect
         (map
          (lambda (x)
            (maps-rest source target
                       (cons
                        (cons next x)
                        pas)
                       rest
                       to-1
                       to-collect))
          (maps-1 source target pas next))))))

(define (maps source target)
  (make-lattice
   (maps-rest source
              target
              '()
              (lattice->elements source)
              (lambda (x) (list (map cdr x)))
              (lambda (x) (apply append x)))
   (lexico (lattice->cmp target))))

(define (count-maps source target)
  (maps-rest source
             target
             '()
             (lattice->elements source)
             (lambda (x) 1)
             sum))

(define (sum lst)
  (if (null? lst)
      0
      (+ (car lst) (sum (cdr lst)))))

(define (run k)
  (let* ((l2
          (make-lattice '(low high)
                        (lambda (lhs rhs)
                          (case lhs
                            ((low)
                             (case rhs
                               ((low)
                                'equal)
                               ((high)
                                'less)
                               (else
                                (error 'make-lattice "base" rhs))))
                            ((high)
                             (case rhs
                               ((low)
                                'more)
                               ((high)
                                'equal)
                               (else
                                (error 'make-lattice "base" rhs))))
                            (else
                             (error 'make-lattice "base" lhs))))))
         (l3 (maps l2 l2))
         (l4 (maps l3 l3)))
    (count-maps l2 l2)
    (count-maps l3 l3)
    (count-maps l2 l3)
    (count-maps l3 l2)
    (case k
      ((33) (count-maps l3 l3))
      ((44) (count-maps l4 l4))
      ((45) (let ((l5 (maps l4 l4)))
              (count-maps l4 l5)))
      ((54) (let ((l5 (maps l4 l4)))
              (count-maps l5 l4)))
      ((55) (let ((l5 (maps l4 l4)))
              (count-maps l5 l5)))
      (else (error "run: unanticipated problem size" k)))))

(define (main)
  (let* ((count 10)
         (input1 44)
         (output 120549)
         (s2 (number->string count))
         (s1 (number->string input1))
         (name "lattice"))
    (run-r7rs-benchmark
     (string-append name ":" s1 ":" s2)
     count
     (lambda () (run (hide count input1)))
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
