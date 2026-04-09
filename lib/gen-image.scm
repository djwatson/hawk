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
    (write (eval datum #f)))
  (newline)
  (flush-output-port)
  (repl))

(save-and-die repl "img.scm.bc" #t)


