(import (scheme base) (prefix (hawk sys) sys:))
(define getter
  (lambda ()
    66))
(define use
  (lambda ()
    (let ((f getter))
      (f))))
(sys:WRITE (use))
