(define-library (scheme r5rs)
  (import (rename (only (scheme base)
                *
                +
                -
                /
                <
                <=
                =
                =>
                >
                >=
                abs
                and
                append
                apply
                assoc
                assq
                assv
                begin
                boolean?
                caar
                cadr
                call-with-current-continuation
                call-with-values
                car
                case
                cdar
                cddr
                cdr
                ceiling
                char->integer
                char-ready?
                char?
                close-input-port
                close-output-port
                complex?
                cond
                cons
                current-input-port
                current-output-port
                define
                define-syntax
                denominator
                do
                dynamic-wind
                else
                eof-object?
                eq?
                equal?
                eqv?
                even?
                exact?
                exact
                for-each
                gcd
                if
                inexact?
                inexact
                input-port?
                integer->char
                integer?
                lambda
                lcm
                length
                let
                let*
                let-syntax
                letrec
                letrec-syntax
                list
                list->string
                list->vector
                list-ref
                list-tail
                list?
                make-string
                make-vector
                map
                max
                member
                memq
                memv
                min
                modulo
                negative?
                newline
                not
                null?
                number->string
                number?
                numerator
                odd?
                or
                output-port?
                pair?
                peek-char
                positive?
                procedure?
                quasiquote
                quote
                quotient
                rational?
                rationalize
                read-char
                real?
                remainder
                reverse
                round
                set!
                set-car!
                set-cdr!
                string
                string->list
                string->number
                string->symbol
                string-append
                string-copy
                string-fill!
                string-length
                string-ref
                string-set!
                string<=?
                string<?
                string=?
                string>=?
                string>?
                string?
                substring
                char=?
                char<?
                char<=?
                char>?
                char>=?
                symbol->string
                symbol?
                syntax-rules
                truncate
                values
                vector
                vector->list
                vector-fill!
                vector-length
                vector-ref
                vector-set!
                vector?
                write-char
                zero?)
                  (inexact exact->inexact)
                  (exact inexact->exact))
          (only (r7expander native) null-environment scheme-report-environment)
          (scheme repl)
          (only (scheme char)
                char-alphabetic?
                char-ci<=?
                char-ci<?
                char-ci=?
                char-ci>=?
                char-ci>?
                char-downcase
                char-lower-case?
                char-numeric?
                char-upcase
                char-upper-case?
                char-whitespace?
                string-ci<=?
                string-ci<?
                string-ci=?
                string-ci>=?
                string-ci>?)
          (only (scheme complex) angle magnitude make-polar make-rectangular real-part) (scheme cxr)
          (only (scheme eval) eval)
          (only (scheme file)
                call-with-input-file
                call-with-output-file
                open-input-file
                open-output-file
                with-input-from-file
                with-output-to-file) (only (scheme inexact) acos asin atan cos log sin sqrt tan)
          (only (scheme lazy) delay force) (scheme load) (scheme read)
          (only (scheme write) display write))
  (export * + - / < <= = => > >= abs and append apply assoc assq assv begin boolean? caar cadr
          call-with-current-continuation call-with-values car case cdar cddr cdr ceiling
          char->integer char-ready? char? close-input-port close-output-port complex? cond cons
          current-input-port current-output-port define define-syntax denominator do dynamic-wind
          else eof-object? eq? equal? eqv? even? exact? for-each gcd if inexact? input-port?
          integer->char integer? lambda lcm length let let* let-syntax letrec letrec-syntax list
          list->string list->vector list-ref list-tail list? make-string make-vector map max member
          memq memv min modulo negative? newline not null? number->string number? numerator odd? or
          output-port? pair? peek-char positive? procedure? quasiquote quote quotient rational?
          rationalize read-char real? remainder reverse round set! set-car! set-cdr! string
          string->list string->number string->symbol string-append string-copy string-fill!
          string-length string-ref string-set! string<=? string<? string=? string>=? string>?
          string? substring char=? char<? char<=? char>? char>=? symbol->string symbol? syntax-rules
          truncate values vector vector->list vector-fill! vector-length vector-ref vector-set!
          vector? write-char zero? char-alphabetic? char-ci<=? char-ci<? char-ci=? char-ci>=?
          char-ci>? char-downcase char-lower-case? char-numeric? char-upcase char-upper-case?
          char-whitespace? string-ci<=? string-ci<? string-ci=? string-ci>=? string-ci>? angle
          magnitude make-polar make-rectangular real-part caaaar caaadr caaar caadar caaddr caadr
          cadaar cadadr cadar caddar cadddr caddr cdaaar cdaadr cdaar cdadar cdaddr cdadr cddaar
          cddadr cddar cdddar cddddr cdddr eval call-with-input-file call-with-output-file
          open-input-file open-output-file with-input-from-file with-output-to-file acos asin atan
          cos log sin sqrt tan delay force load read interaction-environment display write
          exact->inexact inexact->exact null-environment scheme-report-environment))
