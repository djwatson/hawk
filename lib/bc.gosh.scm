(import (scheme base)
        (scheme write)
        (read)
        (syntax)
        (expand)
        (scheme process-context)
        (scheme file)
        (match)
        (srfi 69)
        (srfi 1)
        ;; gauche
        (rename (only (binary io) write-f64) (write-f64 write-double)))



(include "bc.scm")

(display "Compiling:")
(display (cdr (command-line)))
(newline)
(for-each compile-file (cdr (command-line)))
