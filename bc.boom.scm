(define use-bootstrap #t)
(define (format str . rest)
  (display str)
  (display rest)
  (newline))
(define pretty-print display)
(include "bc.scm")
