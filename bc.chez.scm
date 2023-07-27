(define (write-u8 c p)
  (put-u8 p c))

(define (open-output-file f) (open-file-output-port f (file-options no-fail) ))
(define arithmetic-shift (lambda (i c) (bitwise-arithmetic-shift i c)))

(define (write-double d p)
  (define bv (make-bytevector 8))
  (bytevector-ieee-double-native-set! bv 0 d)
  (put-bytevector p bv))
(include "bc.scm")
(display (cdr (command-line)))
(case-sensitive #f)
(for-each (lambda (x) (compile-file x #t)) (cdr (command-line)))



