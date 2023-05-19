;;;;;;;;;;;;;;chicken stuff
(import (r7rs))

(import (chicken foreign))
(import (chicken process-context))

;; (define write-double
;;   (foreign-lambda* long ((double x))
;; 		   "long ret;"
;; 		   "memcpy(&ret, &x, 8);"
;; 		   "C_return(ret);"))

(include "bc.scm")
(display (command-line-arguments))
(for-each compile-file (command-line-arguments))

