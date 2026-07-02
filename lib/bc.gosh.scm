(import (scheme base) (scheme write) (scheme read) (scheme complex) (r7expand) (library) (builders)
        (expander) (scheme cxr) (scheme process-context) (scheme file) (srfi 69) (srfi 1)
        (write-double))

(include "bc.scm")
(include "expander-init.scm")
(library-paths (append '("." "srfi2" "./expand") (library-paths)))

(define args (cdr (command-line)))
(define dump-bc (not (not (member "--list" args))))
(define files (filter (lambda (arg) (not (string=? arg "--list"))) args))

(display "Compiling:")
(display files)
(newline)

(for-each (compile-file dump-bc) files)
