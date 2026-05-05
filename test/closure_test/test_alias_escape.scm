(import (scheme base) (prefix (hawk sys) sys:))
(letrec* ((bar (lambda () 7)))
  (let ((g bar))
    (sys:WRITE (g))))
