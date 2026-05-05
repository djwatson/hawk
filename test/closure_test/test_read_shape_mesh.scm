(import (scheme base) (prefix (hawk sys) sys:))
(letrec* ((driver
            (lambda (port)
              (letrec* ((skip-line (lambda () port))
                        (skip-whitespace (lambda () port))
                        (skip-whitespace-and-comments
                          (lambda ()
                            (letrec* ((loop
                                        (lambda ()
                                          (begin
                                            (skip-line)
                                            (skip-whitespace)
                                            port))))
                              (loop))))
                        (read-list
                          (lambda ()
                            (letrec* ((loop
                                        (lambda ()
                                          (begin
                                            (skip-whitespace-and-comments)
                                            port))))
                              (loop))))
                        (read-one
                          (lambda ()
                            (read-list))))
                (read-one)))))
  (sys:WRITE (driver 303)))
