;;;;;;;;;;;;;;chicken stuff
(import (r7rs))

(import (chicken process-context))

;; This could be used to get full write-double support,
;; but it requires compiling.
;;
;; (import (chicken foreign))
;; (define memcpy-double
;;   (foreign-lambda* long ((double x))
;; 		   "long ret;"
;; 		   "memcpy(&ret, &x, 8);"
;; 		   "C_return(ret);"))
(define (write-double d p)
  (cond
    ((= d 1.0) (write-u64 #x3ff0000000000000 p))
    ((nan? d) (write-u64 #x7ff8000000000 p))
    ((infinite? d) (write-u64 #x7ff8000000000 p))
    (else (error "Can't write double:" d))))

(include "bc.scm")
(display (command-line-arguments))
(for-each compile-file (command-line-arguments))

