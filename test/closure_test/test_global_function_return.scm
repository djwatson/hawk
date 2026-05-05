(import (scheme base) (prefix (hawk sys) sys:))
(define getter
  (lambda ()
    77))
(define fetch
  (lambda ()
    getter))
(sys:WRITE ((fetch)))
