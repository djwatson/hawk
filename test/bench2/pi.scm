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

;;; PI -- Compute PI using bignums.

;; See http://mathworld.wolfram.com/Pi.html for the various algorithms.


(define (square x)
  (* x x))

(define (square-root x)
  (call-with-values
   (lambda ()
     (exact-integer-sqrt x))
   (lambda (q r)
     q)))

(define (quartic-root x)
  (square-root (square-root x)))


;;; Compute pi using the 'brent-salamin' method.

(define (pi-brent-salamin nb-digits)
  (let ((one (expt 10 nb-digits)))
    (let loop ((a one)
               (b (square-root (quotient (square one) 2)))
               (t (quotient one 4))
               (x 1))
      (if (= a b)
          (quotient (square (+ a b)) (* 4 t))
          (let ((new-a (quotient (+ a b) 2)))
            (loop new-a
                  (square-root (* a b))
                  (- t
                     (quotient
                      (* x (square (- new-a a)))
                      one))
                  (* 2 x)))))))

;;; Compute pi using the quadratically converging 'borwein' method.

(define (pi-borwein2 nb-digits)
  (let* ((one (expt 10 nb-digits))
         (one^2 (square one))
         (one^4 (square one^2))
         (sqrt2 (square-root (* one^2 2)))
         (qurt2 (quartic-root (* one^4 2))))
    (let loop ((x (quotient
                   (* one (+ sqrt2 one))
                   (* 2 qurt2)))
               (y qurt2)
               (p (+ (* 2 one) sqrt2)))
      (let ((new-p (quotient (* p (+ x one))
                             (+ y one))))
        (if (= x one)
            new-p
            (let ((sqrt-x (square-root (* one x))))
              (loop (quotient
                     (* one (+ x one))
                     (* 2 sqrt-x))
                    (quotient
                     (* one (+ (* x y) one^2))
                     (* (+ y one) sqrt-x))
                    new-p)))))))

;;; Compute pi using the quartically converging 'borwein' method.

(define (pi-borwein4 nb-digits)
  (let* ((one (expt 10 nb-digits))
         (one^2 (square one))
         (one^4 (square one^2))
         (sqrt2 (square-root (* one^2 2))))
    (let loop ((y (- sqrt2 one))
               (a (- (* 6 one) (* 4 sqrt2)))
               (x 8))
      (if (= y 0)
          (quotient one^2 a)
          (let* ((t1 (quartic-root (- one^4 (square (square y)))))
                 (t2 (quotient
                      (* one (- one t1))
                      (+ one t1)))
                 (t3 (quotient
                      (square (quotient (square (+ one t2)) one))
                      one))
                 (t4 (+ one
                        (+ t2
                           (quotient (square t2) one)))))
            (loop t2
                  (quotient
                   (- (* t3 a) (* x (* t2 t4)))
                   one)
                  (* 4 x)))))))

;;; Try it.

(define (pies n m s)
  (if (< m n)
      '()
      (let ((bs (pi-brent-salamin n))
            (b2 (pi-borwein2 n))
            (b4 (pi-borwein4 n)))
        (cons (list b2 (- bs b2) (- b4 b2))
              (pies (+ n s) m s)))))

(define (main)
  (let* ((count 100)
         (input1 50)
         (input2 500)
         (input3 50)
         (output '((314159265358979323846264338327950288419716939937507
     -54
     124)
    (31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170673
     -51
     -417)
    (3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067982148086513282306647093844609550582231725359408122
     -57
     -819)
    (314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848111745028410270193852110555964462294895493038195
     -76
     332)
    (31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679821480865132823066470938446095505822317253594081284811174502841027019385211055596446229489549303819644288109756659334461284756482337867831652712019089
     -83
     477)
    (3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067982148086513282306647093844609550582231725359408128481117450284102701938521105559644622948954930381964428810975665933446128475648233786783165271201909145648566923460348610454326648213393607260249141268
     -72
     -2981)
    (314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848111745028410270193852110555964462294895493038196442881097566593344612847564823378678316527120190914564856692346034861045432664821339360726024914127372458700660631558817488152092096282925409171536431
     -70
     -2065)
    (31415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679821480865132823066470938446095505822317253594081284811174502841027019385211055596446229489549303819644288109756659334461284756482337867831652712019091456485669234603486104543266482133936072602491412737245870066063155881748815209209628292540917153643678925903600113305305488204665213841469519415116089
     -79
     1687)
    (3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067982148086513282306647093844609550582231725359408128481117450284102701938521105559644622948954930381964428810975665933446128475648233786783165271201909145648566923460348610454326648213393607260249141273724587006606315588174881520920962829254091715364367892590360011330530548820466521384146951941511609433057270365759591953092186117381932611793105118542
     -92
     -2728)
    (314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848111745028410270193852110555964462294895493038196442881097566593344612847564823378678316527120190914564856692346034861045432664821339360726024914127372458700660631558817488152092096282925409171536436789259036001133053054882046652138414695194151160943305727036575959195309218611738193261179310511854807446237996274956735188575272489122793818301194907
     -76
     -3726)))
         (s4 (number->string count))
         (s3 (number->string input3))
         (s2 (number->string input2))
         (s1 (number->string input1))
         (name "pi"))
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
