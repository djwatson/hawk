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

;;; Compute digits of PI using a straightforward implementation of
;;; the Chudnovsky brothers algorithm; see
;;; http://www.craig-wood.com/nick/articles/pi-chudnovsky/



(define ch-A 13591409)
(define ch-B 545140134)
(define ch-C 640320)
(define ch-C^3 (expt 640320 3))
(define ch-D 12)

(define (ch-split a b)
  (if (= 1 (- b a))
      (let ((g (* (- (* 6 b) 5) (- (* 2 b) 1) (- (* 6 b) 1))))
        (list g
              (quotient (* ch-C^3 (expt b 3)) 24)
              (* (expt -1 b) g (+ (* b ch-B) ch-A))))
      (let* ((mid (quotient (+ a b) 2))
             (gpq1 (ch-split a mid))
             (gpq2 (ch-split mid b))
             (g1 (car gpq1)) (p1 (cadr gpq1)) (q1 (caddr gpq1))
             (g2 (car gpq2)) (p2 (cadr gpq2)) (q2 (caddr gpq2)))
        (list (* g1 g2)
              (* p1 p2)
              (+ (* q1 p2) (* q2 g1))))))

(define (integer-sqrt x)
  (call-with-values
   (lambda ()
     (exact-integer-sqrt x))
   (lambda (q r)
     q)))

(define (pi digits)
  (let* ((num-terms (exact (floor (+ 2 (/ digits 14.181647462)))))
         (sqrt-C (integer-sqrt (* ch-C (expt 100 digits)))))
    (let* ((gpq (ch-split 0 num-terms))
           (g (car gpq)) (p (cadr gpq)) (q (caddr gpq)))
      (quotient (* p ch-C sqrt-C) (* ch-D (+ q (* p ch-A)))))))

(define (pies n m s)
  (if (< m n)
      '()
      (cons (pi n)
            (pies (+ n s) m s))))

(define (main)
  (let* ((count 1000)
         (input1 50)
         (input2 500)
         (input3 50)
         (output '(314159265358979323846264338327950288419716939937510
 31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679
 3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067982148086513282306647093844609550582231725359408128
 314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848111745028410270193852110555964462294895493038196
 31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679821480865132823066470938446095505822317253594081284811174502841027019385211055596446229489549303819644288109756659334461284756482337867831652712019091
 3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067982148086513282306647093844609550582231725359408128481117450284102701938521105559644622948954930381964428810975665933446128475648233786783165271201909145648566923460348610454326648213393607260249141273
 314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848111745028410270193852110555964462294895493038196442881097566593344612847564823378678316527120190914564856692346034861045432664821339360726024914127372458700660631558817488152092096282925409171536436
 31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679821480865132823066470938446095505822317253594081284811174502841027019385211055596446229489549303819644288109756659334461284756482337867831652712019091456485669234603486104543266482133936072602491412737245870066063155881748815209209628292540917153643678925903600113305305488204665213841469519415116094
 3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067982148086513282306647093844609550582231725359408128481117450284102701938521105559644622948954930381964428810975665933446128475648233786783165271201909145648566923460348610454326648213393607260249141273724587006606315588174881520920962829254091715364367892590360011330530548820466521384146951941511609433057270365759591953092186117381932611793105118548
 314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848111745028410270193852110555964462294895493038196442881097566593344612847564823378678316527120190914564856692346034861045432664821339360726024914127372458700660631558817488152092096282925409171536436789259036001133053054882046652138414695194151160943305727036575959195309218611738193261179310511854807446237996274956735188575272489122793818301194912))
         (s4 (number->string count))
         (s3 (number->string input3))
         (s2 (number->string input2))
         (s1 (number->string input1))
         (name "chudnovsky"))
    (run-r7rs-benchmark
     (string-append name ":" s1 ":" s2 ":" s3 ":" s4)
     count
     (lambda ()
       (pies (hide count input1)
             (hide count input2)
             (hide count input3)))
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
