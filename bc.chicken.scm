;;;;;;;;;;;;;;chicken stuff
(import (r7rs))
(import (srfi 28)) ;; basic format
(import (srfi 151)) ;; bitwise-ops

(import (chicken foreign))

;; (define write-double
;;   (foreign-lambda* long ((double x))
;; 		   "long ret;"
;; 		   "memcpy(&ret, &x, 8);"
;; 		   "C_return(ret);"))

(define (put-bytevector p v) (display v p))
(include "bc.scm")
