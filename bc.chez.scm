(define (write-u8 c p)
  (put-u8 p c))

(define (open-output-file f) (open-file-output-port f (file-options no-fail) ))
(define arithmetic-shift (lambda (i c) (bitwise-arithmetic-shift i c)))

(load-shared-object "./libwrite_double.so")
(define write-double
  (foreign-procedure "memcpy_double"
		     (double) long)) 
(include "bc.scm")
(display (cdr (command-line)))
(for-each compile-file (cdr (command-line)))


