(import (scheme base) (scheme eval) (scheme write) (scheme read) (scheme file) (scheme case-lambda)
        (scheme process-context) (prefix (hawk sys) sys:) (hawk) (scheme repl))

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
  (library-paths-set! (append (sys:FOREIGN_CALL '(gc_obj "hawk_command_line_prepend_paths" ()))
                              (library-paths)
                              (sys:FOREIGN_CALL '(gc_obj "hawk_default_library_paths" ()))
                              (sys:FOREIGN_CALL '(gc_obj "hawk_command_line_append_paths" ())))))

(define default-import
  '(import (scheme base) (scheme case-lambda) (scheme char) (scheme complex) (scheme cxr)
           (scheme eval) (scheme file) (scheme inexact) (scheme lazy) (scheme load)
           (scheme process-context) (scheme read) (scheme repl) (scheme time) (scheme write)
           (scheme r5rs)))

(define (program-forms program)
  (let ((forms (read-file-forms program)))
    (if (and (pair? forms) (pair? (car forms)) (eq? 'import (caar forms)))
        forms
        (cons default-import forms))))

(define (replace-scm-suffix filename)
  (let ((len (string-length filename)))
    (if (and (>= len 4) (string=? (substring filename (- len 4) len) ".scm"))
        (substring filename 0 (- len 4))
        (error "--exe input must end in .scm" filename))))

(define (path-basename path)
  (let ((len (string-length path)))
    (let loop ((i (- len 1)))
      (cond
        ((< i 0) path)
        ((char=? (string-ref path i) #\/) (substring path (+ i 1) len))
        (else (loop (- i 1)))))))

(define (write-exe-image-source source image compressed?)
  (call-with-output-file source
    (lambda (port)
      (display "#include <stddef.h>\n#include <stdint.h>\nconst uint8_t embedded_image[] = {\n#embed "
               port)
      (write image port)
      (display "\n};\nconst size_t embedded_image_size = sizeof(embedded_image);\nconst bool embedded_image_compressed = "
               port)
      (display (if compressed? "true" "false") port)
      (display ";\nconst bool embedded_image_is_program = true;\n" port))))

(define (compile-exe program)
  (let* ((output (replace-scm-suffix program))
         (image (string-append output ".hawk-image.bc"))
         (source (string-append output ".hawk-image.c"))
         (compressed? (sys:FOREIGN_CALL '(bool "hawk_have_zstd" ())))
         (embedded-image (if compressed? (string-append image ".zstd") image)))
    (write-exe-image-source source (path-basename embedded-image) compressed?)
    (sys:FOREIGN_CALL '(int32 "hawk_dump_image_and_make_exe" (gc_obj gc_obj gc_obj gc_obj))
                      (lambda () ((compile (program-forms program) #f #f)) (flush-output-port))
                      image
                      source
                      output)))

(define main-entry
  (case-lambda
    (() (apply-command-line-flags) (repl))
    ((program compile-to-exe?)
      (apply-command-line-flags)
      (if compile-to-exe?
          (compile-exe program)
          (let* ((final-forms (program-forms program))
                 (list? (sys:FOREIGN_CALL '(gc_obj "hawk_command_line_list" ())))
                 (code (compile final-forms #f list?)))
            (unless list?
              ;; Flush trace cache when in program mode:
              ;; Restart the whole program from fresh trace state.
              (flush-trace-cache)
              (code))
            (flush-output-port))))))

(save-image-and-die main-entry "../boot/img.scm.bc" 19)
