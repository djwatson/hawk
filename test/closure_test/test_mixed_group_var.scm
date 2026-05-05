(import (scheme base) (prefix (hawk sys) sys:))
(letrec* ((id (lambda (x) x)))
  (let ((x (id 9)))
    (letrec* ((bar (lambda () x))
              (foo (lambda () (bar))))
      (let ((g bar))
        (begin
          (sys:WRITE (foo))
          (sys:WRITE (g)))))))
