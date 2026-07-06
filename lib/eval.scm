(import (except (scheme base) syntax-error) (scheme write) (srfi 1) (scheme file)
        (scheme process-context) (scheme read) (r7expand) (scheme case-lambda)
        (rename (library) (library-paths lib:library-paths)) (builders) (expander)
        (prefix (hawk sys) sys:) (srfi 69))

(define (features) feature-list) ;; grab from library

(define (add-feature feat) (add-feature! feat))

(define (environment . lst)
  (define env (make-toplevel-environment 'env))
  (expand-repl `(import ,@lst) env)
  env)
(include "bc.scm")
(include "expander-init.scm")

(define interaction-environment
  (let ((env #f))
    (lambda ()
      (unless env
        (set! env
          (environment '(scheme base)
                       '(scheme case-lambda)
                       '(scheme char)
                       '(scheme complex)
                       '(scheme cxr)
                       '(scheme eval)
                       '(scheme file)
                       '(scheme inexact)
                       '(scheme lazy)
                       '(scheme load)
                       '(scheme process-context)
                       '(scheme read)
                       '(scheme repl)
                       '(scheme time)
                       '(scheme write)
                       '(scheme r5rs))))
      env)))

(define (library-paths) (lib:library-paths))
(define (library-paths-set! paths) (lib:library-paths paths))

(for-each add-feature
          '(r7rs exact-closed
                 exact-complex
                 ieee-float ;;full-unicode
                 ratios
                 posix
                 hawk))
(define (scheme-report-environment version)
  (unless (= 5 version)
    (error "scheme-report-environment supports only version 5" version))
  (environment '(scheme r5rs)))

(define (null-environment version)
  (unless (= 5 version)
    (error "null-environment supports only version 5" version))
  (environment '(only (scheme r5rs)
                      syntax-rules
                      define
                      quasiquote
                      let
                      let*
                      letrec
                      letrec-syntax
                      do
                      case
                      cond
                      and
                      or
                      delay
                      force
                      lambda
                      begin
                      if
                      quote
                      define-syntax
                      let-syntax
                      set!)))

(define (flush-trace-cache) (sys:FOREIGN_CALL '(int32 "vm_trace_reset" ())))

(define (compile foo env dump)
  (let* ((ir
            (build-begin (list (if env (expand-repl foo env) (expand-program foo "PROGRAM")))))
         (roots (compile-ir-to-bitcode ir))
         (payload (roots->runtime-payload roots))
         (clo (sys:FOREIGN_CALL '(gc_obj "scm_emit_bitcode_closure" (gc_obj)) payload)))
    (when dump (for-each print-bc roots))
    clo))

(define (eval sexp env) ((compile sexp env #f)))

(define jit
  (case-lambda
    (() (if (sys:FOREIGN_CALL '(bool "vm_jit_enabled" ())) 'enabled 'disabled))
    ((val)
      (sys:FOREIGN_CALL '(bool "vm_jit_set_enabled" (bool)) (not (not val)))
      (jit))))

(define (load file)
  (define (read-file)
    (let read-file-rec ((sexps '()))
      (define next (read))
      (if (eof-object? next) (reverse sexps) (read-file-rec (cons next sexps)))))
  (define input (with-input-from-file file read-file))
  (eval `(begin ,@input) (interaction-environment)))

(define (save-image-and-die restart name compress-level)
  (sys:FOREIGN_CALL '(int32 "gc_dump_image_and_die" (gc_obj gc_obj gc_obj))
                    restart
                    name
                    compress-level))
