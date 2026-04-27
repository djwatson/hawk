(define hawk-sys-symbols
  '(ADD SUB
        DIV
        MUL
        MOD
        LT
        GT
        EQ
        LTE
        GTE
        NUM_EQ
        EQV
        QUOTIENT
        GUARD
        LOAD
        STORE
        LOAD_CHAR
        STORE_CHAR
        ALLOC
        INTEGER_CHAR
        CHAR_INTEGER
        INEXACT
        TRUNCATE
        EXACT
        FOREIGN_CALL
        APPLY
        CALLCC
        CALLCC_RESUME
        WRITE
        HALT
        ;; These are kinda combined symbols
        CONS
        RECT))

(define (install-hawk-sys!)
  (unless (library-exists? '(hawk sys))
    (make-library '(hawk sys))
    (with-library '(hawk sys)
                  (lambda ()
                    (define (install-native! keyword)
                      (let ((env (current-toplevel-environment))) (extend-environment! keyword env))
                      (library-export keyword))
                    (for-each install-native! hawk-sys-symbols)))))

(expander-setup)
(install-hawk-sys!)
