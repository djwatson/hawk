(import (scheme base) (scheme eval) (scheme write) (scheme read) (prefix (hawk sys) sys:))
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
    (display (eval datum (environment))))
  (newline)
  (flush-output-port)
  (repl))

;; Bootstrap the expander
(eval '(import (scheme base) (scheme case-lambda) (scheme char) (scheme complex) (scheme cxr)
               (scheme eval) (scheme file) (scheme inexact) (scheme lazy) (scheme load)
               (scheme process-context) (scheme read) (scheme repl) (scheme time) (scheme write)
               (scheme r5rs))
      (environment))
(save-and-die repl "img.scm.bc" #f)


