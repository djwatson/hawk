(define subnormal (exact (/ 2.2250738585072014e-308 2.0)))
(display (if (= subnormal (/ 1 (expt 2 1023)))
             "subnormal-ok"
             "subnormal-fail"))
(newline)
