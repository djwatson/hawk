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
        NUMEQ
        EQV
        QUOTIENT
        GUARD
        GUARDMASK
        ABC
        LOAD
        STORE
        FLVECTOR_SET
        LOAD_CHAR
        FLVECTOR_REF
        STORE_CHAR
        LOAD_BYTE
        STORE_BYTE
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
        CAR
        CDR
        CONS
        RECT))

(define hawk-lib-symbols
  '(add-feature library-paths
                library-paths-set!
                compile
                flush-trace-cache
                jit
                save-image-and-die))

(define (install-hawk-library! name symbols variable-library-name)
  (unless (library-exists? name)
    (make-library name)
    (with-library name
                  (lambda ()
                    (define (install-native! keyword)
                      (let ((env (current-toplevel-environment)))
                        (install-toplevel-binding! keyword
                                                   (build-variable keyword variable-library-name)
                                                   env))
                      (library-export keyword))
                    (for-each install-native! symbols)))))

(expander-setup)
(install-hawk-library! '(hawk sys) hawk-sys-symbols '(hawk sys))
(install-hawk-library! '(hawk) hawk-lib-symbols "")
