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

;;; BROWSE -- Benchmark to create and browse through
;;; an AI-like data base of units.



(define (lookup key table)
  (let loop ((x table))
    (if (null? x)
        #f
        (let ((pair (car x)))
          (if (eq? (car pair) key)
              pair
              (loop (cdr x)))))))

(define *properties* '())

(define (get key1 key2)
  (let ((x (lookup key1 *properties*)))
    (if x
        (let ((y (lookup key2 (cdr x))))
          (if y
              (cdr y)
              #f))
        #f)))

(define (put key1 key2 val)
  (let ((x (lookup key1 *properties*)))
    (if x
        (let ((y (lookup key2 (cdr x))))
          (if y
              (set-cdr! y val)
              (set-cdr! x (cons (cons key2 val) (cdr x)))))
        (set! *properties*
              (cons (list key1 (cons key2 val)) *properties*)))))

(define *current-gensym* 0)

(define (generate-symbol)
  (set! *current-gensym* (+ *current-gensym* 1))
  (string->symbol (number->string *current-gensym*)))

(define (append-to-tail! x y)
  (if (null? x)
      y
      (do ((a x b)
           (b (cdr x) (cdr b)))
          ((null? b)
           (set-cdr! a y)
           x))))

(define (tree-copy x)
  (if (not (pair? x))
      x
      (cons (tree-copy (car x))
            (tree-copy (cdr x)))))

;;; n is # of symbols
;;; m is maximum amount of stuff on the plist
;;; npats is the number of basic patterns on the unit
;;; ipats is the instantiated copies of the patterns

(define *rand* 21)

(define (init n m npats ipats)
  (let ((ipats (tree-copy ipats)))
    (do ((p ipats (cdr p)))
        ((null? (cdr p)) (set-cdr! p ipats)))
    (do ((n n (- n 1))
         (i m (cond ((zero? i) m)
                    (else (- i 1))))
         (name (generate-symbol) (generate-symbol))
         (a '()))
        ((= n 0) a)
      (set! a (cons name a))
      (do ((i i (- i 1)))
          ((zero? i))
        (put name (generate-symbol) #f))
      (put name
           'pattern
           (do ((i npats (- i 1))
                (ipats ipats (cdr ipats))
                (a '()))
               ((zero? i) a)
             (set! a (cons (car ipats) a))))
      (do ((j (- m i) (- j 1)))
          ((zero? j))
        (put name (generate-symbol) #f)))))

(define (browse-random)
  (set! *rand* (remainder (* *rand* 17) 251))
  *rand*)

(define (randomize l)
  (do ((a '()))
      ((null? l) a)
    (let ((n (remainder (browse-random) (length l))))
      (cond ((zero? n)
             (set! a (cons (car l) a))
             (set! l (cdr l))
             l)
            (else
             (do ((n n (- n 1))
                  (x l (cdr x)))
                 ((= n 1)
                  (set! a (cons (cadr x) a))
                  (set-cdr! x (cddr x))
                  x)))))))

(define (my-match pat dat alist)
  (cond ((null? pat)
         (null? dat))
        ((null? dat) '())
        ((or (eq? (car pat) '?)
             (eq? (car pat)
                  (car dat)))
         (my-match (cdr pat) (cdr dat) alist))
        ((eq? (car pat) '*)
         (or (my-match (cdr pat) dat alist)
             (my-match (cdr pat) (cdr dat) alist)
             (my-match pat (cdr dat) alist)))
        (else (cond ((not (pair? (car pat)))
                     (cond ((eq? (string-ref (symbol->string (car pat)) 0)
                                 #\?)
                            (let ((val (assq (car pat) alist)))
                              (cond (val (my-match (cons (cdr val)
                                                         (cdr pat))
                                                   dat alist))
                                    (else (my-match (cdr pat)
                                                    (cdr dat)
                                                    (cons (cons (car pat)
                                                                (car dat))
                                                          alist))))))
                           ((eq? (string-ref (symbol->string (car pat)) 0)
                                 #\*)
                            (let ((val (assq (car pat) alist)))
                              (cond (val (my-match (append (cdr val)
                                                           (cdr pat))
                                                   dat alist))
                                    (else
                                     (do ((l '()
                                             (append-to-tail!
                                              l
                                              (cons (if (null? d)
                                                        '()
                                                        (car d))
                                                    '())))
                                          (e (cons '() dat) (cdr e))
                                          (d dat (if (null? d) '() (cdr d))))
                                         ((or (null? e)
                                              (my-match (cdr pat)
                                                        d
                                                        (cons
                                                         (cons (car pat) l)
                                                         alist)))
                                          (if (null? e) #f #t)))))))

                           ;; fix suggested by Manuel Serrano
                           ;; (cond did not have an else clause);
                           ;; this changes the run time quite a bit

                           (else #f)))
                    (else (and
                           (pair? (car dat))
                           (my-match (car pat)
                                     (car dat) alist)
                           (my-match (cdr pat)
                                     (cdr dat) alist)))))))

(define database
  (randomize
   (init 100 10 4 '((a a a b b b b a a a a a b b a a a)
                    (a a b b b b a a
                       (a a)(b b))
                    (a a a b (b a) b a b a)))))

(define (browse pats)
  (investigate
   database
   pats)
  (map string->number (map symbol->string database)))

(define (investigate units pats)
  (do ((units units (cdr units)))
      ((null? units))
    (do ((pats pats (cdr pats)))
        ((null? pats))
      (do ((p (get (car units) 'pattern)
              (cdr p)))
          ((null? p))
        (my-match (car pats) (car p) '())))))

(define (main)
  (let* ((count 2000)
         (input1 '((*a ?b *b ?b a *a a *b *a)
		  (*a *b *b *a (*a) (*b))
		  (? ? * (b a) * ? ?)))
         (output '(837 177
       1090
       617
       661
       749
       628
       56
       826
       408
       1035
       474
       320
       452
       672
       991
       155
       122
       793
       221
       716
       727
       848
       309
       144
       936
       100
       881
       287
       430
       23
       771
       232
       804
       958
       650
       1068
       1057
       463
       276
       1046
       1002
       199
       34
       738
       210
       540
       397
       342
       364
       782
       683
       89
       375
       166
       595
       892
       705
       507
       639
       331
       188
       243
       441
       1013
       1079
       67
       298
       386
       573
       859
       133
       760
       12
       529
       815
       111
       496
       45
       265
       925
       903
       254
       78
       551
       606
       485
       518
       419
       870
       562
       1
       353
       980
       694
       914
       969
       947
       584
       1024))
         (s2 (number->string count))
         (s1 "")
         (name "browse"))
    (run-r7rs-benchmark
     (string-append name ":" s2)
     count
     (lambda () (browse (hide count input1)))
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
