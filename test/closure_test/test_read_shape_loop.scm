(import (scheme base) (prefix (hawk sys) sys:))
(letrec* ((driver
            (lambda (port)
              (letrec* ((skip-line (lambda () port))
                        (skip-whitespace-and-comments
                          (lambda ()
                            (letrec* ((loop
                                        (lambda ()
                                          (begin
                                            (skip-line)
                                            port))))
                              (loop)))))
                (skip-whitespace-and-comments)))))
  (sys:WRITE (driver 202)))
