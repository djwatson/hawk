;; Given a flonum, writes it to a bytevector.
;; This is possible to do portably in r6rs, but not r7rs. Doh.

(define-library (write-double)
  (import (scheme base))
  (cond-expand (gauche (import (rename (only (binary io) write-f64) (write-f64 write-double))))
               (hawk (import (prefix (hawk sys) sys:))))
  (export write-double)
  (begin
    (cond-expand (hawk (define (write-double value port)
                         (write-bytevector (sys:FOREIGN_CALL '(gc_obj "scm_double_bytes" (double))
                                                             value)
                                           port)))
                 (gauche)
                 (else (error "write-double unimplemented")))))
