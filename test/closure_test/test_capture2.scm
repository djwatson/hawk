(import (scheme base) (prefix (hawk sys) sys:))
(let ((x 1) (y 2))
  (letrec* ((foo (lambda () (begin x y))))
    (sys:WRITE (foo))))
