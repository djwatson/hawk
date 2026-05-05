(import (scheme base) (prefix (hawk sys) sys:))
(letrec* ((driver
            (lambda (port)
              (letrec* ((skip-whitespace (lambda () port))
                        (read-one (lambda () (skip-whitespace))))
                (read-one)))))
  (sys:WRITE (driver 101)))
