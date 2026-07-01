(import (scheme base) (scheme eval) (scheme write) (scheme read) (scheme file) (scheme case-lambda)
        (scheme process-context) (prefix (hawk sys) sys:) (hawk))

;; This file contains the main image file.  It is compiled to an image
;; by a host scheme, then dumped out as a GC image after
;; re-initializing the expander (because the expander does not support
;; serializing its own state, it's much simpler that way).

(define (repl)
  (display "repl> ")
  (flush-output-port)
  (guard (obj (else
                (display "Caught error:")
                (display (error-object-message obj))
                (newline)
                (display (error-object-irritants obj))
                (newline)
                #f))
    (let ((datum (read)))
      (when (eof-object? datum) (exit 0))
      (write (eval datum (interaction-environment)))
      (newline)
      (flush-output-port)))
  (repl))

(define (read-file-forms filename)
  (call-with-input-file filename
    (lambda (port)
      (let loop ((form (read port)) (acc '()))
        (if (eof-object? form) (reverse acc) (loop (read port) (cons form acc)))))))

(define (apply-command-line-flags)
  (for-each (lambda (feat-string) (add-feature (string->symbol feat-string)))
            (sys:FOREIGN_CALL '(gc_obj "hawk_command_line_features" ())))
  (library-paths-set!
    (append (sys:FOREIGN_CALL '(gc_obj "hawk_command_line_prepend_paths" ()))
            (library-paths)
            (sys:FOREIGN_CALL '(gc_obj "hawk_command_line_append_paths" ())))))

(define main-entry
  (case-lambda
    (() (repl))
    ((program)
      (apply-command-line-flags)
      (let* ((forms (read-file-forms program))
             (prepend
                '(import (scheme base) (scheme case-lambda) (scheme char) (scheme complex)
                         (scheme cxr) (scheme eval) (scheme file) (scheme inexact) (scheme lazy)
                         (scheme load) (scheme process-context) (scheme read) (scheme repl)
                         (scheme time) (scheme write) (scheme r5rs)))
             (final-forms
                (if (and (pair? forms) (pair? (car forms)) (eq? 'import (caar forms)))
                    forms
                    (cons prepend forms)))
             (list? (sys:FOREIGN_CALL '(gc_obj "hawk_command_line_list" ())))
             (code (compile final-forms #f list?)))
        (unless list?
          ;; Flush trace cache when in program mode:
          ;; Restart the whole program from fresh trace state.
          (flush-trace-cache)
          (code))
        (flush-output-port)))))

(save-image-and-die main-entry "../boot/img.scm.bc" 19)
