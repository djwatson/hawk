(define ratio (/ (+ (expt 2 2000) 1)
                 (expt 2 2000)))
(define value (inexact ratio))
(define arithmetic-value (+ ratio 0.0))

(display (if (and (= value 1.0)
                  (= arithmetic-value 1.0)
                  (not (nan? value)))
             "rational-to-double-ok"
             "rational-to-double-fail"))
(newline)

(define (check ratio expected)
  (if (not (and (= (inexact ratio) expected)
                (= (+ ratio 0.0) expected)))
      (error "rational-to-double mismatch" ratio expected)))

(check 1/2 0.5)
(check -1/2 -0.5)
(check 4/3 1.3333333333333333)
(check (/ (+ (expt 2 2000) (expt 2 1999) 1) (expt 2 2000)) 1.5)
;; Discarded bits must round the numerator up, including an odd halfway case.
(check (/ (+ (expt 2 54) 3) (expt 2 55)) 0.5000000000000001)
(check (/ (+ (expt 2 54) 6) (expt 2 55)) 0.5000000000000002)
(check (/ 1 (expt 2 1074)) (/ 2.2250738585072014e-308 (expt 2.0 52)))
(display "fraction-checks-ok")
(newline)
