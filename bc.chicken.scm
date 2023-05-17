;;;;;;;;;;;;;;chicken stuff
(import (r7rs))

(import (chicken foreign))

;; (define write-double
;;   (foreign-lambda* long ((double x))
;; 		   "long ret;"
;; 		   "memcpy(&ret, &x, 8);"
;; 		   "C_return(ret);"))

(include "bc.scm")
