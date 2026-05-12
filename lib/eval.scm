(import (except (scheme base) syntax-error) (scheme write) (srfi 1) (scheme file)
        (scheme process-context) (scheme read) (r7expand) (library) (builders) (expander)
        (prefix (hawk sys) sys:) (srfi 69))

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
(library-paths '("." "lib/srfi2"))

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

(define (eval foo env)
  ;; (display "EVAL:")
  ;; (display foo)
  ;; (display "\n")
  ;; (flush-output-port)

  (let* ((ir
            (build-begin (list (if env
                                   (expand-repl foo (interaction-environment))
                                   (expand-program foo "PROGRAM")))))
         ;; (_
         ;;    (begin
         ;;      (display "Expand done\n" (current-error-port))
         ;;      (display ir (current-error-port))
         ;;      (flush-output-port (current-error-port))))
         (roots (compile-ir-to-bitcode ir))
         ;; (_
         ;;    (begin
         ;;      (display "Compile done\n" (current-error-port))
         ;;      (flush-output-port (current-error-port))))
         ;;(unused (begin (for-each print-bc roots) (flush-output-port)))
         (payload (roots->runtime-payload roots))
         (clo (sys:FOREIGN_CALL '(gc_obj "scm_emit_bitcode_closure" (gc_obj)) payload)))
    ;; (display "runtime init done\n" (current-error-port))
    ;; (flush-output-port (current-error-port))

    ;; Flush trace cache when in program mode:
    ;; Restart the whole program from fresh trace state.
    (unless env (sys:FOREIGN_CALL '(int32 "vm_trace_reset" ())))
    (clo)))

(define (load file)
  (define (read-file)
    (let read-file-rec ((sexps '()))
      (define next (read))
      (if (eof-object? next) (reverse sexps) (read-file-rec (cons next sexps)))))
  (define input (with-input-from-file file read-file))
  (eval input (interaction-environment)))
