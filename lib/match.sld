;; TODO use ... instead of ___

;; Simple match, in syntax-rules.
;; Patterns:
;; x              literal
;; ,x             bind match to x.
;; ,(cat x)       call catamorphism on x (you always have to explicitly specify the catamorphism.
;; ,(? guard x)   If guard fails, the pattern fails.  Otherwise bind match to x.
;; ,x ___         Dotted pattern.  Bind to list.
;;  . <pat>       Tail patterns should work

;; You use an overloaded quasiquote with ___ support to expand ___.  It's just bound to a list,
;; there is no error checking for list dimention.
;; Also unsupported: ,x ___ ___  on destruction.
(define-library (match)
  (export match ilength)
  (import (scheme base) (scheme write))
  (include "match.scm"))
