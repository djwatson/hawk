(import (scheme base)
        (scheme write)
        (scheme read)
        (r7expand)
        (library)
        (builders)
        (expander)
        (scheme cxr)
        (scheme process-context)
        (scheme file)
        (match)
        (srfi 69)
        (srfi 1)
        ;; gauche
        (rename (only (binary io) write-f64) (write-f64 write-double)))

(include "bc.scm")

(expander-setup)

(define args (cdr (command-line)))
(define dump-bc (not (not (member "--dump" args))))
(define files (filter (lambda (arg) (not (string=? arg "--dump"))) args))

(display "Compiling:")
(display files)
(newline)

(for-each (compile-file dump-bc) files)
