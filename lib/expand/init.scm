(let ()
(define native-env #f)
(make-library '(r7expander native))
(with-library '(r7expander native)
              (lambda ()
                (define (install-native! keyword)
                  (let ((env (current-toplevel-environment)))
                    (install-toplevel-binding! keyword (build-variable keyword "") env))
                  (library-export keyword))
                (set! native-env (current-toplevel-environment))

                (for-each install-native!
                          ;; (scheme base)
                          ;; 4.2.6. Dynamic bindings
                          '(make-parameter
                            ;; 6.1. Equivalence predicates
                            eq?
                            eqv?
                            equal?
                            ;; 6.2. Numbers
                            number?
                            complex?
                            real?
                            rational?
                            integer?
                            exact?
                            inexact?
                            exact-integer?
                            exact
                            inexact
                            =
                            <
                            >
                            <=
                            >=
                            zero?
                            positive?
                            negative?
                            odd?
                            even?
                            min
                            max
                            +
                            -
                            *
                            /
                            abs
                            floor-quotient
			    modulo
			    remainder
			    quotient
                            floor-remainder
                            floor/
                            truncate-quotient
                            truncate-remainder
                            truncate/
                            gcd
                            lcm
                            numerator
                            denominator
                            floor
                            ceiling
                            truncate
                            round
                            rationalize
                            exact-integer-sqrt
                            square
                            expt
                            number->string
                            string->number
                            ;; 6.3. Booleans
                            boolean?
                            boolean=?
                            not
                            ;; 6.4 Pairs and lists
                            pair?
                            cons
                            car
                            cdr
                            set-car!
                            set-cdr!
                            caar
                            cadr
                            cdar
                            cddr
                            null?
                            list?
                            make-list
                            list
                            length
                            append
                            reverse
                            list-tail
                            list-ref
                            list-set!
                            list-copy
                            memq
                            memv
                            member
                            assq
                            assv
                            assoc
                            ;; 6.5. Symbols
                            symbol?
                            symbol=?
                            symbol->string
                            string->symbol
                            ;; 6.6. Characters
                            char?
                            char->integer
                            integer->char
                            char=?
                            char<?
                            char>?
                            char<=?
                            char>=?
                            ;; 6.7. Strings
                            string?
                            string
                            make-string
                            string-length
                            string-ref
                            string-set!
                            string=?
                            string<?
                            string>?
                            string<=?
                            string>=?
                            string-append
                            string->list
                            list->string
                            string-copy
                            string-copy!
                            string-fill!
                            ;; 6.8. Vectors
                            vector?
                            vector
                            make-vector
                            vector-length
                            vector-ref
                            vector-set!
                            list->vector
                            vector->list
                            string->vector
                            vector->string
                            vector-copy
                            vector-copy!
                            vector-append
                            vector-fill!
                            ;; 6.9. Bytevectors
                            bytevector?
                            make-bytevector
                            bytevector
                            bytevector-length
                            bytevector-u8-ref
                            bytevector-u8-set!
                            bytevector-copy
                            bytevector-copy!
                            bytevector-append
                            utf8->string
                            string->utf8
                            ;; 6.10. Control features
                            procedure?
                            apply
                            map
                            for-each
                            string-map
                            string-for-each
                            vector-map
                            vector-for-each
                            call-with-current-continuation
                            values
                            call-with-values
                            dynamic-wind
                            ;; record runtime helpers
                            make-record
                            make-record-type
                            record-constructor
                            record?
                            record-ref
                            record-set!
                            ;; 6.11. Exceptions
                            with-exception-handler
                            raise
                            raise-continuable
                            error
                            error-object?
                            error-object-message
                            error-object-irritants
                            read-error?
                            file-error?
                            ;; 6.13. Input and output
                            current-input-port
                            current-output-port
                            current-error-port
                            call-with-port
                            port?
                            input-port?
                            output-port?
                            textual-port?
                            binary-port?
                            input-port-open?
                            output-port-open?
                            close-port
                            close-input-port
                            close-output-port
                            open-input-string
                            open-output-string
                            get-output-string
                            open-input-bytevector
                            open-output-bytevector
                            get-output-bytevector
                            eof-object?
                            eof-object
                            read-char
                            peek-char
                            char-ready?
                            read-line
                            read-string
                            read-u8
                            peek-u8
                            u8-ready?
                            read-bytevector
                            read-bytevector!
                            newline
                            write-char
                            write-string
                            write-u8
                            write-bytevector
                            flush-output-port
                            ;; (scheme cxr)
                            caaar
                            caadr
                            cadar
                            caddr
                            cdaar
                            cdadr
                            cddar
                            cdddr
                            caaaar
                            caaadr
                            caadar
                            caaddr
                            cadaar
                            cadadr
                            caddar
                            cadddr
                            cdaaar
                            cdaadr
                            cdadar
                            cdaddr
                            cddaar
                            cddadr
                            cdddar
                            cddddr
                            ;; (scheme file)
                            call-with-input-file
                            call-with-output-file
                            delete-file
                            file-exists?
                            open-binary-input-file
                            open-binary-output-file
                            open-input-file
                            open-output-file
                            with-input-from-file
                            with-output-to-file
                            ;; (scheme process-context)
                            command-line
                            emergency-exit
                            exit
                            get-environment-variable
                            get-environment-variables
                            ;; (scheme read)
                            read
                            ;; (scheme write)
                            write
                            write-simple
                            write-shared
                            display
                            ;; (scheme inexact)
                            acos
                            asin
                            atan
                            cos
                            exp
                            finite?
                            infinite?
                            log
                            nan?
                            sin
                            sqrt
                            tan
                            ;; (scheme char)
                            char-alphabetic?
                            char-ci<=?
                            char-ci<?
                            char-ci=?
                            char-ci>=?
                            char-ci>?
                            char-downcase
                            char-foldcase
                            char-lower-case?
                            char-numeric?
                            char-upcase
                            char-upper-case?
                            char-whitespace?
                            digit-value
                            string-ci<=?
                            string-ci<?
                            string-ci=?
                            string-ci>=?
                            string-ci>?
                            string-downcase
                            string-foldcase
                            string-upcase
                            ;; (scheme complex)
                            angle
                            magnitude
                            imag-part
                            make-polar
                            make-rectangular
                            real-part
                            ;; (scheme eval)
                            eval
                            environment
                            ;; (scheme lazy)
                            delay
                            delay-force
                            force
                            make-promise
                            promise?
                            ;; (scheme load)
                            load
                            ;; (scheme repl)
                            interaction-environment
                            ;; (scheme time)
                            current-jiffy
                            current-second
                            jiffies-per-second
                            ;; (scheme r5rs) not elsewhere
                            null-environment
                            scheme-report-environment))))

(make-library '(r7expander builtin))
(with-library '(r7expander builtin)
              (lambda ()
                (define builtin-env (current-toplevel-environment))
                (define (install-builtin! keyword transformer)
                  (let ((env (current-toplevel-environment)))
                    (let ((expander (make-expander transformer env)))
                      (install-expander! keyword expander env)))
                  (library-export keyword))
		
		(library-import '(r7expander native))

                ;; TODO

		(install-builtin! 'if-expand
				  (er-macro-transformer
				   (lambda (form rename compare)
				     (unless (= (length form) 4)
				       (error "malformed if-expand" form))
				     (let ((condition (cadr form)))
				       (if (and (pair? condition)
						(compare (car condition) (rename 'library)))
					   (if (library-exists? (unwrap-syntax (cadr condition)))
					       (list-ref form 2)
					       (list-ref form 3))
					   (if (memq (unwrap-syntax condition) feature-list)
					       (list-ref form 2)
					       (list-ref form 3)))))))
                (install-builtin! 'begin-include
                                  (lambda (form env)
                                    (unless (and (>= (length form) 2) (string? (cadr form)))
                                      (error "malformed begin-include" form))
                                    (with-current-directory-from-file (cadr form)
                                      (lambda (resolved)
                                        (build-begin
                                          (map (lambda (subform) (expand subform env))
                                               (cddr form)))))))
                (install-builtin! 'include
                                  (er-macro-transformer (lambda (form rename compare)
                                                          (unless (every string? (cdr form))
                                                            (error "malformed include" form))
                                                          `(,(rename 'begin)
                                                             ,@(map
                                                                 (lambda (filename)
                                                                   (let ((resolved (resolve-path
                                                                                    filename)))
                                                                     `(,(make-identifier
                                                                          'begin-include
                                                                          builtin-env)
                                                                       ,resolved
                                                                       ,@(read-file-forms
                                                                          resolved))))
                                                                 (cdr form))))))
                (let ()
                  (define (expand-lambda-clause clause env)
                    (let ((formals (car clause)) (body (cdr clause)))
                      (unless (pair? body) (error "expression required" clause))
                      (let ((formal-list
                              (let loop ((formals formals) (acc '()))
                                (cond
                                  ((null? formals) acc)
                                  ((pair? formals)
                                    (and (identifier? (car formals))
                                         (loop (cdr formals) `(,(car formals) . ,acc))))
                                  (else
                                    (and (identifier? formals) `(,formals . ,acc)))))))
                        (unless formal-list
                          (error "invalid formal arguments" formals))
                        (let ((new-env (extend-environment formal-list env)))
                          (let ((vars
                                  (let rec ((formals formals))
                                    (cond
                                      ((null? formals) '())
                                      ((pair? formals)
                                        `(,(cdr (assq-environment (car formals) new-env))
                                          .
                                          ,(rec (cdr formals))))
                                      (else (cdr (assq-environment formals new-env)))))))
                            (let ((body-env (extend-environment '() new-env)))
                              (let-values (((definitions body-exprs)
                                           (let ((body
                                                   (map (lambda (form)
                                                          (expand form body-env))
                                                        body)))
                                             (let ()
                                               ;; Internal define RHS must be expanded after all
                                               ;; definition names in the body are installed.
                                               (define (expand-definition form)
                                                 (cond
                                                   ((ir-quote? form) form)
                                                   ((ir-lambda? form) form)
                                                   ((ir-define? form)
                                                     (let ((exp (expand (ir-define-exp form) body-env)))
                                                       (build-define (ir-define-var form)
                                                                     (expand-definition exp)
                                                                     (ir-define-ann form))))
                                                   ((ir-begin? form)
                                                     (build-begin (map expand-definition
                                                                       (ir-begin-exps form))
                                                                  (ir-begin-ann form)))
                                                   (else form)))

                                               (define (definition? form)
                                                 (cond
                                                   ((ir-define? form) #t)
                                                   ((ir-begin? form)
                                                     (every definition? (ir-begin-exps form)))
                                                   (else #f)))

                                               (define (splice-definition definition)
                                                 (cond
                                                   ((ir-define? definition)
                                                     (list definition))
                                                   ((ir-begin? definition)
                                                     (append-map splice-definition
                                                                 (ir-begin-exps definition)))
                                                   (else '())))

                                               (let ((body (map expand-definition body)))
                                                 (let loop ((rest body) (definitions '()))
                                                   (cond
                                                     ((null? rest)
                                                       (error "expression required" (last body)))
                                                     ((definition? (car rest))
                                                       (loop (cdr rest)
                                                             `(,(splice-definition (car rest))
                                                               .
                                                               ,definitions)))
                                                     (else
                                                       (values (apply append (reverse definitions))
                                                               rest)))))))))
                                (list vars
                                      (if (null? definitions)
                                          (if (null? (cdr body-exprs))
                                              (car body-exprs)
                                              (build-begin body-exprs))
                                          (build-letrec*
                                            (map (lambda (d)
                                                   (list (ir-define-var d)
                                                         (ir-define-exp d)
                                                         #f))
                                                 definitions)
                                            (build-begin body-exprs)))))))))))

                  (define (expand-lambda-clauses clauses env)
                    (build-lambda (map (lambda (clause) (expand-lambda-clause clause env))
                                       clauses)))

                  (install-builtin! 'case-lambda
                                    (lambda (form env)
                                      (unless (>= (length form) 2)
                                        (error "malformed case-lambda" form))
                                      (expand-lambda-clauses (cdr form) env)))

                  (install-builtin! 'lambda
                                    (lambda (form env)
                                      (unless (>= (length form) 3)
                                        (error "malformed lambda" form))
                                      (expand-lambda-clauses (list (cdr form)) env))))

                (install-builtin! 'define-record-type
                                  (er-macro-transformer
                                    (lambda (form rename compare)
                                      (unless (and (>= (length form) 4)
                                                   (identifier? (list-ref form 1))
                                                   (list? (list-ref form 2))
                                                   (every identifier? (list-ref form 2))
                                                   (identifier? (list-ref form 3))
                                                   (every (lambda (field-spec)
                                                            (and (list? field-spec)
                                                                 (every identifier? field-spec)
                                                                 (let ((l (length field-spec)))
                                                                   (or (= l 2) (= l 3)))))
                                                          (list-tail form 4))
                                                   (let ((fields (map car (list-tail form 4))))
                                                     (every (lambda (formal) (memq formal fields))
                                                            (cdr (list-ref form 2)))))
                                        (error "malformed define-record-type" form))
                                      (let* ((type (list-ref form 1))
                                             (constructor-spec (list-ref form 2))
                                             (constructor (car constructor-spec))
                                             (constructor-tags (cdr constructor-spec))
                                             (predicate (list-ref form 3))
                                             (field-specs (list-tail form 4))
                                             (field-tags (map car field-specs))
                                             (field-names (map unwrap-syntax field-tags))
                                             (thing 'thing)
                                             (value 'value))
                                        (define (native-id sym)
                                          (make-identifier sym native-env))
                                        (define (field-index tag)
                                          (let loop ((i 1) (field-names field-names))
                                            (cond
                                              ((null? field-names)
                                                (error "constructor field not found" tag))
                                              ((eq? (unwrap-syntax tag) (car field-names)) i)
                                              (else (loop (+ i 1) (cdr field-names))))))
                                        (define (constructor-setters record tags)
                                          (map (lambda (tag)
                                                 `(,(native-id 'record-set!)
                                                   ,record
                                                   ,(field-index tag)
                                                   ,tag))
                                               tags))
                                        (define (expand-field-specs specs index)
                                          (if (null? specs)
                                              '()
                                              (let* ((field-spec (car specs))
                                                     (accessor (list-ref field-spec 1)))
                                                (if (= (length field-spec) 2)
                                                    (cons
                                                      `(,(rename 'define) ,accessor
                                                         (,(rename 'lambda) (,thing)
                                                           (,(rename 'if)
                                                             (,predicate ,thing)
                                                             (,(native-id 'record-ref) ,thing ,index)
                                                             (,(rename 'error) "Invalid accessor"))))
                                                      (expand-field-specs (cdr specs) (+ index 1)))
                                                    (let ((modifier (list-ref field-spec 2)))
                                                      (cons
                                                        `(,(rename 'define) ,accessor
                                                           (,(rename 'lambda) (,thing)
                                                             (,(rename 'if)
                                                               (,predicate ,thing)
                                                               (,(native-id 'record-ref) ,thing ,index)
                                                               (,(rename 'error) "Invalid accessor"))))
                                                        (cons
                                                          `(,(rename 'define) ,modifier
                                                             (,(rename 'lambda) (,thing ,value)
                                                               (,(rename 'if)
                                                                 (,predicate ,thing)
                                                                 (,(native-id 'record-set!)
                                                                   ,thing
                                                                   ,index
                                                                   ,value)
                                                                 (,(rename 'error) "Invalid modifier"))))
                                                          (expand-field-specs
                                                            (cdr specs)
                                                    (+ index 1)))))))))
                                        (let ((record (rename 'record))
                                              (rtd (rename 'rtd)))
                                        `(,(rename 'begin)
                                           (,(rename 'define)
                                             ,type
                                             (,(native-id 'make-record-type)
                                               ',(unwrap-syntax type)
                                               ',field-names))
                                           (,(rename 'define) ,constructor
                                             ((,(rename 'lambda) (,rtd)
                                                (,(rename 'lambda) ,constructor-tags
                                                  ((,(rename 'lambda) (,record)
                                                   (,(native-id 'record-set!) ,record 0 ,rtd)
                                                   ,@(constructor-setters
                                                       record
                                                       constructor-tags)
                                                   ,record)
                                                   (,(native-id 'make-record)
                                                     ,(+ (length field-tags) 1)))))
                                              ,type))
                                           (,(rename 'define) ,predicate
                                             (,(rename 'lambda) (,thing)
                                               (,(rename 'if)
                                                 (,(native-id 'record?) ,thing)
                                                 (,(rename 'eq?)
                                                   (,(native-id 'record-ref) ,thing 0)
                                                   ,type)
                                                 #f)))
                                           ,@(expand-field-specs field-specs 1)))))))
                (for-each library-export '(syntax-rules _ ...))
                (install-builtin! 'define
                                  (lambda (form env)
                                    (unless (and (= (length form) 3) (identifier? (cadr form)))
                                      (error "malformed define" form))
                                    (let ((formal (cadr form)) (expr (caddr form)))
                                      (extend-environment! formal env)
                                      (let ((name (cdr (assq-environment formal env))))
                                        ;; Delay expansion for non-toplevel defines so
                                        ;; internal definitions can see later bindings.
                                        (build-define
                                          name
                                          (if (or (toplevel-environment? env)
                                                  (and (variable? name)
                                                       (not (eq? #f (variable-library-name name)))))
                                              (expand expr env)
                                              expr))))))

                (install-builtin! 'quote
                                  (lambda (form env)
                                    (unless (= (length form) 2) (error "malformed quote" form))
                                    (let ((obj (unwrap-syntax (cadr form))))
                                      (build-quote obj))))

                (install-builtin! 'if
                                  (lambda (form env)
                                    (case (length form)
                                      ((3)
                                        (build-conditional
                                          (expand (cadr form) env)
                                          (expand (caddr form) env)
                                          (build-void)
                                          #f))
                                      ((4)
                                        (build-conditional
                                          (expand (cadr form) env)
                                          (expand (caddr form) env)
                                          (expand (cadddr form) env)
                                          #f))
                                      (else (error "malformed if" form)))))

                (install-builtin! 'set!
                                  (lambda (form env)
                                    (unless (and (= (length form) 3) (identifier? (cadr form)))
                                      (error "malformed set!" form))
                                    (let ((name (cdr (assq-environment (cadr form) env)))
                                          (value (expand (caddr form) env)))
                                      (if (and (variable? name)
                                               (not (eq? #f (variable-library-name name))))
                                          (build-global-assignment name value)
                                          (build-lexical-assignment name value)))))

                (install-builtin! 'begin
                                  (lambda (form env)
                                    (let ((forms (cdr form)))
                                      (build-begin
                                        (map (lambda (form) (expand form env)) forms)))))

                (let ()
                  (define (interpret-transformer-spec spec env)
                    (cond
                      ((eq? (unwrap-syntax (car spec)) 'syntax-rules)
                        (make-expander (interpret-syntax-rules spec env) env))
                      (else (error "unknown transformer spec" spec))))

                  (define (interpret-syntax-rules spec spec-env)
                    (er-macro-transformer (lambda (form rename compare)

                                            ;; missing features:
                                            ;; - placeholder
                                            ;; - more syntax check (e.g. non-linearity of pattern variables)

                                            (define-values (ellipsis ellipsis-env literals rules)
                                              (if (list? (cadr spec))
                                                  (values (make-identifier '...
                                                                           builtin-env)
                                                          builtin-env
                                                          (cadr spec)
                                                          (cddr spec))
                                                  (values (cadr spec)
                                                          spec-env
                                                          (caddr spec)
                                                          (cdddr spec))))

                                            ;; p ::= var | constant | #(p ...) | (p <ellipsis> . p) | (p . p)

                                            (define-syntax case-pattern
                                               (syntax-rules (variable-pattern constant-pattern vector-pattern
                                                              ellipsis-pattern pair-pattern)
                                                 ((_ pat
                                                     ((variable-pattern var) . var-body)
                                                     ((constant-pattern obj) . const-body)
                                                     ((vector-pattern vec) . vector-body)
                                                     ((ellipsis-pattern rep succ) . ellipsis-body)
                                                     ((pair-pattern head tail) . pair-body))
                                                  (let ((tmp pat))
                                                    (cond
                                                      ((identifier? tmp)
                                                        (let ((var tmp)) . var-body))
                                                      ((vector? tmp)
                                                        (let ((vec (vector->list tmp))) . vector-body))
                                                      ((not (pair? tmp))
                                                        (let ((obj tmp)) . const-body))
                                                      ((and (pair? (cdr pat))
                                                            (identifier? (cadr pat))
                                                            (identifier=? (cadr pat)
                                                                          spec-env
                                                                          ellipsis
                                                                          ellipsis-env))
                                                        (let ((rep (car pat)) (succ (cddr pat)))
                                                          .
                                                          ellipsis-body))
                                                      (else
                                                        (let ((head (car tmp)) (tail (cdr tmp)))
                                                          .
                                                          pair-body)))))))

                                            (define (pattern-variables pat) ; pattern -> ((var . depth))
                                              (let go ((pat pat) (depth 0) (acc '()))
                                                (case-pattern pat
                                                              ((variable-pattern var)
                                                               (alist-cons var depth acc))
                                                              ((constant-pattern obj) acc)
                                                              ((vector-pattern vec-pat)
                                                               (go vec-pat depth acc))
                                                              ((ellipsis-pattern rep-pat succ-pat)
                                                               (go rep-pat
                                                                   (+ depth 1)
                                                                   (go succ-pat depth acc)))
                                                              ((pair-pattern car-pat cdr-pat)
                                                               (go car-pat
                                                                   depth
                                                                   (go cdr-pat depth acc))))))

                                            (define (syntax-check pattern template) ; pattern * template -> undefined
                                              (let ((pattern-variables (pattern-variables (cdr pattern)))
                                                    (template-variables
                                                       (pattern-variables template)))
                                                (for-each (lambda (var-depth-in-template)
                                                            (let ((var (car var-depth-in-template)))
                                                              (let ((var-depth-in-pattern
                                                                       (assq var pattern-variables)))
                                                                (when var-depth-in-pattern
                                                                  (when (< (cdr var-depth-in-template)
                                                                           (cdr var-depth-in-pattern))
                                                                    (error "syntax-rules: malformed rule"
                                                                           `(,pattern ,template)
                                                                           (unwrap-syntax (car var-depth-in-template))))))))
                                                          template-variables)))

                                            (define (pattern-match pat form) ; pattern * obj -> ((var . obj))
                                              (call/cc (lambda (return)
                                                         (let match ((pat pat) (form form))
                                                           (let* ((acc '())
                                                                  (push!
                                                                     (lambda (x)
                                                                       (set! acc (cons x acc)))))
                                                             (let walk ((pat pat) (form form))
                                                               (case-pattern pat
                                                                             ((variable-pattern var)
                                                                              (if (memq var
                                                                                        literals) ; comparing literal identifiers using eq?
                                                                                  (unless (identifier=?
                                                                                             form
                                                                                             (current-use-environment)
                                                                                             var
                                                                                             (current-meta-environment))
                                                                                    (return #f))
                                                                                  (push! `(,var .
                                                                                                ,form))))
                                                                             ((constant-pattern obj)
                                                                              (unless (equal? pat
                                                                                              form)
                                                                                (return #f)))
                                                                             ((vector-pattern vec-pat)
                                                                              (unless (vector? form)
                                                                                (return #f))
                                                                              (walk vec-pat
                                                                                    (vector->list form)))
                                                                             ((ellipsis-pattern rep-pat
                                                                                                succ-pat)
                                                                              (let ()
                                                                                (define (reverse* x)
                                                                                  (let loop ((x x)
                                                                                             (acc
                                                                                                '()))
                                                                                    (if (pair? x)
                                                                                        (loop (cdr x)
                                                                                              (cons (car x)
                                                                                                    acc))
                                                                                        (values acc
                                                                                                x))))
                                                                                (let-values (((rev-pat
                                                                                               last-pat)
                                                                                                (reverse* succ-pat))
                                                                                             ((rev-form
                                                                                               last-form)
                                                                                                (reverse* form)))
                                                                                  (walk last-pat
                                                                                        last-form)
                                                                                  (let ((rep-form
                                                                                           (let loop ((rev-pat
                                                                                                         rev-pat)
                                                                                                      (rev-form
                                                                                                         rev-form))
                                                                                             (cond
                                                                                               ((null? rev-pat)
                                                                                                 (reverse rev-form))
                                                                                               ((null? rev-form)
                                                                                                 (return #f))
                                                                                               (else
                                                                                                 (walk (car rev-pat)
                                                                                                       (car rev-form))
                                                                                                 (loop (cdr rev-pat)
                                                                                                       (cdr rev-form)))))))
                                                                                    (if (null? rep-form)
                                                                                        (let ((variables
                                                                                                 (map car
                                                                                                      (pattern-variables rep-pat))))
                                                                                          (for-each (lambda (var)
                                                                                                      (push! `(,var .
                                                                                                                    ())))
                                                                                                    variables))
                                                                                        (let ((substs
                                                                                                 (map (lambda (obj)
                                                                                                        (match rep-pat
                                                                                                          obj))
                                                                                                      rep-form)))
                                                                                          (let ((variables
                                                                                                   (map car
                                                                                                        (car substs))))
                                                                                            (for-each (lambda (var)
                                                                                                        (push! `(,var .
                                                                                                                      ,(map (lambda (subst)
                                                                                                                              (cdr (assq var
                                                                                                                                         subst)))
                                                                                                                            substs))))
                                                                                                      variables))))))))
                                                                             ((pair-pattern car-pat
                                                                                            cdr-pat)
                                                                              (unless (pair? form)
                                                                                (return #f))
                                                                              (walk car-pat
                                                                                    (car form))
                                                                              (walk cdr-pat
                                                                                    (cdr form)))))
                                                             acc)))))

                                            (define (rewrite-template template subst pattern-variable-depths) ; template * ((var . obj)) -> obj
                                                (let rewrite ((template template))
                                                  (case-pattern template
                                                              ((variable-pattern var)
                                                               (cond
                                                                 ((assq var subst) => cdr)
                                                                 (else (rename var))))
                                                              ((constant-pattern obj) obj)
                                                              ((vector-pattern vec-templ)
                                                               (list->vector (rewrite vec-templ)))
                                                              ((ellipsis-pattern rep-templ
                                                                                 succ-templ)
                                                               (let ((vars-in-templ
                                                                        (map car
                                                                             (pattern-variables rep-templ))))
                                                                  (let ((vars-to-unroll
                                                                          (filter (lambda (var)
                                                                                    (and (assq var subst)
                                                                                         (cond
                                                                                           ((assq var pattern-variable-depths)
                                                                                            =>
                                                                                            (lambda (var-depth)
                                                                                              (> (cdr var-depth) 0)))
                                                                                           (else #f))))
                                                                                  vars-in-templ)))
                                                                   (let ((vals-to-unroll
                                                                            (map (lambda (var)
                                                                                   (cdr (assq var
                                                                                              subst)))
                                                                                 vars-to-unroll)))
                                                                     (let ((new-substs
                                                                              (apply map
                                                                                     (lambda vals
                                                                                       (map cons
                                                                                            vars-to-unroll
                                                                                            vals))
                                                                                     vals-to-unroll)))
                                                                       (let ((base-subst
                                                                               (filter (lambda (var-obj)
                                                                                         (not (memq (car var-obj)
                                                                                                    vars-to-unroll)))
                                                                                       subst))
                                                                             (pattern-variable-depths
                                                                               (map (lambda (var-depth)
                                                                                      (if (memq (car var-depth)
                                                                                                vars-to-unroll)
                                                                                          (cons (car var-depth)
                                                                                                (- (cdr var-depth) 1))
                                                                                          var-depth))
                                                                                    pattern-variable-depths)))
                                                                       (append (map (lambda (subst)
                                                                                      (rewrite-template rep-templ
                                                                                                        (append subst base-subst)
                                                                                                        pattern-variable-depths))
                                                                                    new-substs)
                                                                               (rewrite succ-templ))))))))
                                                              ((pair-pattern car-templ cdr-templ)
                                                               (cons (rewrite car-templ)
                                                                     (rewrite cdr-templ))))))

                                            (let loop ((rules rules))
                                              (if (null? rules)
                                                  (error "no rule matched" form)
                                                  (let ((rule (car rules)))
                                                    (let ((pattern (car rule))
                                                          (template (cadr rule)))
                                                      (syntax-check pattern template)
                                                      (let ((subst (pattern-match (cdr pattern) (cdr form)))
                                                            (pattern-variables (pattern-variables (cdr pattern))))
                                                        (if subst
                                                            (rewrite-template template subst pattern-variables)
                                                            (loop (cdr rules)))))))))))

                  (install-builtin! 'let-syntax
                                    (lambda (form env)
                                      (let ((bindings (cadr form)) (body (cddr form)))
                                        (let ((keywords (map car bindings))
                                              (transformer-specs (map cadr bindings)))
                                          (let ((expanders
                                                   (map (lambda (spec)
                                                          (interpret-transformer-spec spec env))
                                                        transformer-specs)))
                                            (let ((new-env (extend-environment '() env)))
                                              (for-each (lambda (keyword expander)
                                                          (install-expander! keyword
                                                                             expander
                                                                             new-env))
                                                        keywords
                                                        expanders)
                                              (expand `((,(make-identifier 'lambda
                                                                           (current-meta-environment ))
                                                         ()
                                                         ,@body))
                                                      new-env)))))))

                  (install-builtin! 'letrec-syntax
                                    (lambda (form env)
                                      (let ((bindings (cadr form)) (body (cddr form)))
                                        (let ((keywords (map car bindings))
                                              (transformer-specs (map cadr bindings)))
                                          (let ((new-env (extend-environment '() env)))
                                            (let ((expanders
                                                     (map (lambda (spec)
                                                            (interpret-transformer-spec spec
                                                                                        new-env))
                                                          transformer-specs)))
                                              (for-each (lambda (keyword expander)
                                                          (install-expander! keyword
                                                                             expander
                                                                             new-env))
                                                        keywords
                                                        expanders)
                                              (expand `((,(make-identifier 'lambda
                                                                           (current-meta-environment ))
                                                         ()
                                                         ,@body))
                                                      new-env)))))))

                  (install-builtin! 'define-syntax
                                    (lambda (form env)
                                      (let ((keyword (cadr form)) (transformer-spec (caddr form)))
                                        (let ((expander
                                                 (interpret-transformer-spec transformer-spec env)))
                                          (install-expander! keyword expander env)
                                          (build-void)))))

                  (install-builtin! 'syntax-error
                                    (lambda (form _)
                                      (unless (and (>= (length form) 2) (string? (cadr form)))
                                        (error "malformed syntax-error" form))
                                      (apply error (cdr form)))))))



(load-library-from-file "init/scheme/base.sld")
(set! feature-list (cons 'r7rs feature-list))
(load-library-from-file "init/scheme/case-lambda.sld")
(load-library-from-file "init/scheme/char.sld")
(load-library-from-file "init/scheme/complex.sld")
(load-library-from-file "init/scheme/cxr.sld")
(load-library-from-file "init/scheme/eval.sld")
(load-library-from-file "init/scheme/file.sld")
(load-library-from-file "init/scheme/inexact.sld")
(load-library-from-file "init/scheme/lazy.sld")
(load-library-from-file "init/scheme/load.sld")
(load-library-from-file "init/scheme/process-context.sld")
(load-library-from-file "init/scheme/read.sld")
(load-library-from-file "init/scheme/repl.sld")
(load-library-from-file "init/scheme/time.sld")
(load-library-from-file "init/scheme/write.sld")
(load-library-from-file "init/scheme/r5rs.sld")
)
