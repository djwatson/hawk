(define-library (scheme lazy)
  (import (scheme base) (only (r7expander native) force make-promise promise? %make-promise))
  (export delay delay-force force make-promise promise?)
  (begin
    (define-syntax delay-force
       (syntax-rules ()
         ((delay-force expression) (%make-promise #f (lambda () expression)))))

    (define-syntax delay
       (syntax-rules ()
         ((delay expression) (delay-force (%make-promise #t expression)))))))
