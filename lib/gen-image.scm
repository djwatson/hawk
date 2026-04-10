(import (scheme base) (scheme eval) (scheme write) (scheme read) (prefix (hawk sys) sys:)
        (scheme case-lambda))
(define (save-and-die restart name compress)
  (sys:FOREIGN_CALL '(int32 "gc_dump_image_and_die" (gc_obj gc_obj gc_obj))
                    restart
                    name
                    compress))
(define (repl)
  (display "repl> ")
  (flush-output-port)
  (let ((datum (read)))
    (when (eof-object? datum) (exit 0))
    (write (eval datum #f)))
  (newline)
  (flush-output-port)
  (repl))

(define main-entry
  (case-lambda
    (() (repl))
    ((program)
      (let* ((forms (read-file-forms program))
             (prepend
                '(import (scheme base) (scheme case-lambda) (scheme char) (scheme complex)
                         (scheme cxr) (scheme eval) (scheme file) (scheme inexact) (scheme lazy)
                         (scheme load) (scheme process-context) (scheme read) (scheme repl)
                         (scheme time) (scheme write) (scheme r5rs)))
             (final-forms
                (if (and (pair? forms) (pair? (car forms)) (eq? 'import (caar forms)))
                    forms
                    (cons prepend forms))))

        (eval-program final-forms)
        (flush-output-port)))))

(save-and-die main-entry "img.scm.bc" #t)


