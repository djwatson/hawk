(define (write-u8 c p)
  (put-u8 p c))

(define (open-output-file f) (open-file-output-port f (file-options no-fail) ))
(define arithmetic-shift (lambda (i c) (bitwise-arithmetic-shift i c)))
(include "bc.scm")
