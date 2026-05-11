(import (scheme base) (scheme eval) (scheme write) (scheme read) (prefix (hawk sys) sys:)
        (scheme file) (scheme case-lambda) (scheme process-context))

(define (save-and-die restart name compress-level)
  (sys:FOREIGN_CALL '(int32 "gc_dump_image_and_die" (gc_obj gc_obj gc_obj))
                    restart
                    name
                    compress-level))
(define (repl)
  (display "repl> ")
  (flush-output-port)
  (let ((datum (read)))
    (when (eof-object? datum) (exit 0))
    (guard (obj (else
                  (display "Caught error:")
                  (display (error-object-message obj))
                  (newline)
                  (display (error-object-irritants obj))
                  (newline)
                  #f))
      (write (eval datum #t)))
    (newline)
    (flush-output-port)
    (repl)))

(define (read-file-forms filename)
  (call-with-input-file filename
    (lambda (port)
      (let loop ((form (read port)) (acc '()))
        (if (eof-object? form) (reverse acc) (loop (read port) (cons form acc)))))))

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

        (eval final-forms #f)
        (flush-output-port)))))

(save-and-die main-entry "../boot/img.scm.bc" 19)
