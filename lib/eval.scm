(import (except (scheme base) syntax-error) (scheme write) (srfi 1) (scheme file)
        (scheme process-context) (scheme read) (r7expand) (library) (builders) (expander)
        (prefix (hawk sys) sys:) (srfi 69))

(define (write-double d) (error "No write-double"))
(include "bc.scm")
(include "expander-init.scm")
(define repl-env (make-toplevel-environment 'repl))
(expand-repl '(import (scheme base) (scheme case-lambda) (scheme char) (scheme complex) (scheme cxr)
                      (scheme eval) (scheme file) (scheme inexact) (scheme lazy) (scheme load)
                      (scheme process-context) (scheme read) (scheme repl) (scheme time)
                      (scheme write) (scheme r5rs))
             repl-env)
(library-paths '("." "lib/srfi2"))

(define (eval foo env)
  ;; (display "EVAL:")
  ;; (display foo)
  ;; (display "\n")
  ;; (flush-output-port)

  (let* ((ir
            (build-begin (list (if env (expand-repl foo repl-env) (expand-program foo "PROGRAM")))))
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
         (payload (roots->runtime-payload roots))
         (clo (sys:FOREIGN_CALL '(gc_obj "scm_emit_bitcode_closure" (gc_obj)) payload)))
    ;; (display "runtime init done\n" (current-error-port))
    ;; (flush-output-port (current-error-port))

    ;; Flush trace cache when in program mode:
    ;; Restart the whole program from fresh trace state.
    (unless env (sys:FOREIGN_CALL '(int32 "vm_trace_reset" ())))
    (clo)))
