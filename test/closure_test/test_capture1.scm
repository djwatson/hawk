(import (scheme base) (prefix (hawk sys) sys:))
(let ((x 41))
  (letrec* ((foo (lambda () x)))
    (sys:WRITE (foo))))
