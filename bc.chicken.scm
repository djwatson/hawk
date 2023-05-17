;;;;;;;;;;;;;;chicken stuff
(import (r7rs))
(import (srfi 28)) ;; basic format

(import (chicken foreign))

(define use-bootstrap #t)

;; (define write-double
;;   (foreign-lambda* long ((double x))
;; 		   "long ret;"
;; 		   "memcpy(&ret, &x, 8);"
;; 		   "C_return(ret);"))

(include "bc.scm")
