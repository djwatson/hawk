(import (scheme base) (prefix (hawk sys) sys:))
(let ((x 9))
  (letrec* ((bar (lambda () x))
            (foo (lambda () (bar))))
    (let ((g bar))
      (begin
        (sys:WRITE (foo))
        (sys:WRITE (g))))))
