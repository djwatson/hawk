;; Output builders for the expander
;; These functions construct the output representation of expanded code.
;; Uses records to represent the IR, which can be converted to S-expressions.

;; Minimal vector-backed counterpart to define-record-type.
(define-syntax define-struct-type
  (syntax-rules ()
    ((_ tag
        (constructor constructor-tag ...)
        predicate
        (field-tag accessor index) ...)
      (begin
        (define (constructor constructor-tag ...)
          (vector 'tag constructor-tag ...))
        (define (predicate obj)
          (and (vector? obj) (> (vector-length obj) 0) (eq? (vector-ref obj 0) 'tag)))
        (define-struct-field field-tag accessor index) ...))))

(define-syntax define-struct-field
  (syntax-rules ()
    ((_ field-tag accessor index)
      (define (accessor obj) (vector-ref obj index)))))

;; Variable record to track assignments
(define-struct-type var
  (make-variable name assigned library-name)
  variable?
  (name variable-name 1)
  (assigned variable-assigned 2)
  (library-name variable-library-name 3))

(define (set-variable-assigned! var value)
  (vector-set! var 2 value))

(define (build-variable name library-name)
  (make-variable name #f library-name))

;; Tagged-vector helpers for the IR
(define-struct-type app
  (make-ir-application fun-exp arg-exps ann well-known)
  ir-application?
  (fun-exp ir-application-fun 1)
  (arg-exps ir-application-args 2)
  (ann ir-application-ann 3)
  (well-known ir-application-well-known 4))

(define-struct-type if
  (make-ir-conditional test-exp then-exp else-exp ann)
  ir-conditional?
  (test-exp ir-conditional-test 1)
  (then-exp ir-conditional-then 2)
  (else-exp ir-conditional-else 3)
  (ann ir-conditional-ann 4))

(define-struct-type ref
  (make-ir-reference var global? mutable? ann)
  ir-reference?
  (var ir-reference-var 1)
  (global? ir-reference-global? 2)
  (mutable? ir-reference-mutable? 3)
  (ann ir-reference-ann 4))

(define-struct-type set!
  (make-ir-assignment var exp global? ann)
  ir-assignment?
  (var ir-assignment-var 1)
  (exp ir-assignment-exp 2)
  (global? ir-assignment-global? 3)
  (ann ir-assignment-ann 4))

(define-struct-type lambda
  (make-ir-lambda cases name freevars ann well-known)
  ir-lambda?
  (cases ir-lambda-cases 1)
  (name ir-lambda-name 2)
  (freevars ir-lambda-freevars 3)
  (ann ir-lambda-ann 4)
  (well-known ir-lambda-well-known 5))

(define-struct-type let
  (make-ir-let bindings body ann)
  ir-let?
  (bindings ir-let-bindings 1)
  (body ir-let-body 2)
  (ann ir-let-ann 3))

(define-struct-type letrec*
  (make-ir-letrec* bindings body-exps ann)
  ir-letrec*?
  (bindings ir-letrec*-bindings 1)
  (body-exps ir-letrec*-body 2)
  (ann ir-letrec*-ann 3))

(define-struct-type loop
  (make-ir-loop args body name ann)
  ir-loop?
  (args ir-loop-args 1)
  (body ir-loop-body 2)
  (name ir-loop-name 3)
  (ann ir-loop-ann 4))

(define-struct-type quote
  (make-ir-quote datum ann)
  ir-quote?
  (datum ir-quote-datum 1)
  (ann ir-quote-ann 2))

(define-struct-type begin
  (make-ir-begin exps ann)
  ir-begin?
  (exps ir-begin-exps 1)
  (ann ir-begin-ann 2))

(define-struct-type primcall
  (make-ir-primcall name args ann)
  ir-primcall?
  (name ir-primcall-name 1)
  (args ir-primcall-args 2)
  (ann ir-primcall-ann 3))

(define-struct-type void
  (make-ir-void ann)
  ir-void?
  (ann ir-void-ann 1))

(define-struct-type define
  (make-ir-define var exp ann)
  ir-define?
  (var ir-define-var 1)
  (exp ir-define-exp 2)
  (ann ir-define-ann 3))

(define (optional-ann ann)
  (if (null? ann) #f (car ann)))

;; Builder functions that create IR records
(define (build-application fun-exp arg-exps . ann)
  (make-ir-application fun-exp arg-exps (optional-ann ann) #f))

(define (set-ir-application-well-known! ir well-known)
  (vector-set! ir 4 well-known))

(define (set-ir-application-fun! ir fun-exp)
  (vector-set! ir 1 fun-exp))

(define (set-ir-application-args! ir arg-exps)
  (vector-set! ir 2 arg-exps))

(define (build-conditional test-exp then-exp else-exp ann)
  (make-ir-conditional test-exp then-exp else-exp ann))

(define (set-ir-conditional-test! ir test)
  (vector-set! ir 1 test))

(define (set-ir-conditional-then! ir then)
  (vector-set! ir 2 then))

(define (set-ir-conditional-else! ir else)
  (vector-set! ir 3 else))

(define (build-lexical-reference var mutable . ann)
  (make-ir-reference var #f mutable (optional-ann ann)))

(define (build-global-reference var mutable . ann)
  (make-ir-reference var #t mutable (optional-ann ann)))

(define (build-lexical-assignment var exp . ann)
  (set-variable-assigned! var #t)
  (make-ir-assignment var exp #f (optional-ann ann)))

(define (build-global-assignment var exp . ann)
  (set-variable-assigned! var #t)
  (make-ir-assignment var exp #t (optional-ann ann)))

(define (build-set var exp global? . ann)
  (set-variable-assigned! var #t)
  (make-ir-assignment var exp global? (optional-ann ann)))

(define build-lambda
  (case-lambda
    ((cases) (make-ir-lambda cases #f '() #f #f))
    ((cases ann) (make-ir-lambda cases #f '() ann #f))
    ((cases name freevars ann) (make-ir-lambda cases name freevars ann #f))
    ((cases name freevars ann well-known) (make-ir-lambda cases name freevars ann well-known))))

(define (set-ir-lambda-cases! ir cases)
  (vector-set! ir 1 cases))

(define (set-ir-lambda-freevars! ir freevars)
  (vector-set! ir 3 freevars))

(define (set-ir-lambda-well-known! ir well-known)
  (vector-set! ir 5 well-known))

(define (build-let bindings body . ann)
  (if (null? bindings)
      body
      (make-ir-let bindings body (optional-ann ann))))

(define (build-letrec* bindings body-exps . ann)
  (make-ir-letrec* bindings body-exps (optional-ann ann)))

(define (build-loop args body name . ann)
  (make-ir-loop args body name (optional-ann ann)))

(define (set-ir-letrec*-bindings! ir bindings)
  (vector-set! ir 1 bindings))

(define (set-ir-letrec*-body! ir body)
  (vector-set! ir 2 body))

(define (set-ir-loop-args! ir args)
  (vector-set! ir 1 args))

(define (set-ir-loop-body! ir body)
  (vector-set! ir 2 body))

(define (build-quote datum . ann)
  (make-ir-quote datum (optional-ann ann)))

(define (build-begin exps . ann)
  (cond
    ((null? exps) (make-ir-void (optional-ann ann)))
    ((null? (cdr exps)) (car exps))
    (else (make-ir-begin exps (optional-ann ann)))))

(define (build-void . ann) (make-ir-void (optional-ann ann)))

(define (build-define var exp . ann)
  (make-ir-define var exp (optional-ann ann)))

(define (build-primcall name args . ann)
  (make-ir-primcall name args (optional-ann ann)))

(define (set-ir-primcall-args! ir args)
  (vector-set! ir 2 args))

;; In-place walker for IR trees. Pass `c` to transform children.
(define (walk-ir ir c)
  (define (walk-cases cases)
    (map (lambda (clause) (list (car clause) (c (cadr clause)))) cases))
  (cond
    ((ir-application? ir)
      (vector-set! ir 1 (c (ir-application-fun ir)))
      (vector-set! ir 2 (map c (ir-application-args ir))))
    ((ir-conditional? ir)
      (vector-set! ir 1 (c (ir-conditional-test ir)))
      (vector-set! ir 2 (c (ir-conditional-then ir)))
      (vector-set! ir 3 (c (ir-conditional-else ir))))
    ((ir-reference? ir) #t)
    ((ir-assignment? ir) (vector-set! ir 2 (c (ir-assignment-exp ir))))
    ((ir-lambda? ir) (vector-set! ir 1 (walk-cases (ir-lambda-cases ir))))
    ((ir-letrec*? ir)
      (for-each (lambda (val) (set-car! (cdr val) (c (cadr val))))
                (ir-letrec*-bindings ir))
      (vector-set! ir 2 (c (ir-letrec*-body ir)))
      ir)
    ((ir-loop? ir)
      (for-each (lambda (val) (set-car! (cdr val) (c (cadr val))))
                (ir-loop-args ir))
      (vector-set! ir 2 (c (ir-loop-body ir)))
      ir)
    ((ir-let? ir)
      (for-each (lambda (val) (set-car! (cdr val) (c (cadr val))))
                (ir-let-bindings ir))
      (vector-set! ir 2 (c (ir-let-body ir)))
      ir)
    ((ir-quote? ir) #t)
    ((ir-begin? ir) (vector-set! ir 1 (map c (ir-begin-exps ir))))
    ((ir-void? ir) #t)
    ((ir-define? ir) (vector-set! ir 2 (c (ir-define-exp ir))))
    ((ir-primcall? ir) (vector-set! ir 2 (map c (ir-primcall-args ir))))
    (else (error "Invalid IR:" ir)))
  ir)

;; Converter: walks IR records and converts to S-expressions
(define (letrec*-binding-group? binding)
  (and (pair? binding) (pair? (car binding))))

(define (letrec*-binding->sexp binding)
  (let ((var (car binding)))
    (list (if (variable? var) (variable-name var) var)
          (ir->sexp (cadr binding)))))

(define (ir->sexp ir)
  (define (binding-name v)
    (if (variable? v) (variable-name v) v))
  (define (vars->names vars)
    (cond
      ((null? vars) '())
      ((pair? vars) (cons (variable-name (car vars)) (vars->names (cdr vars))))
      (else (variable-name vars))))
  (define (list->sexp lst)
    (cond
      ((null? lst) '())
      ((pair? lst) (cons (ir->sexp (car lst)) (list->sexp (cdr lst))))
      (else (ir->sexp lst))))
  (cond
    ((variable? ir) (variable-name ir))

    ((ir-application? ir)
      (cons (ir->sexp (ir-application-fun ir))
            (map ir->sexp (ir-application-args ir))))

    ((ir-conditional? ir)
      (let ((else-part (ir-conditional-else ir)))
        (if else-part
            `(if ,(ir->sexp (ir-conditional-test ir))
                 ,(ir->sexp (ir-conditional-then ir))
                 ,(ir->sexp (ir-conditional-else ir)))
            `(if ,(ir->sexp (ir-conditional-test ir))
                 ,(ir->sexp (ir-conditional-then ir))
                 #f))))

    ((ir-reference? ir) (variable-name (ir-reference-var ir)))

    ((ir-assignment? ir)
      (let ((var (ir-assignment-var ir)))
        `(set! ,(variable-name var) ,(ir->sexp (ir-assignment-exp ir)))))

    ((ir-lambda? ir)
      (let* ((cases (ir-lambda-cases ir))
             (sexp-cases
               (map (lambda (clause)
                      (let ((vars (car clause))
                            (body (cadr clause)))
                        `(,(vars->names vars) ,(ir->sexp body))))
                    cases)))
        (if (null? (cdr sexp-cases))
            `(lambda ,@(car sexp-cases))
            `(case-lambda ,@sexp-cases))))

    ((ir-let? ir)
      (let ((bindings (ir-let-bindings ir)))
        `(let ,(map (lambda (binding)
                      (list (binding-name (car binding))
                            (ir->sexp (cadr binding))))
                    bindings)
           ,(ir->sexp (ir-let-body ir)))))

    ((ir-letrec*? ir)
      (let ((bindings (ir-letrec*-bindings ir)))
        `(letrec* ,(if (and (pair? bindings) (letrec*-binding-group? (car bindings)))
                       (map (lambda (group) (map letrec*-binding->sexp group)) bindings)
                       (map letrec*-binding->sexp bindings))
           ,(ir->sexp (ir-letrec*-body ir)))))

    ((ir-loop? ir)
      (let ((bindings (ir-loop-args ir))
            (body (ir-loop-body ir))
            (name (ir-loop-name ir)))
        `(letrec* ((,(variable-name name)
                    (lambda ,(vars->names (map car bindings))
                      ,(ir->sexp body))))
           (,(variable-name name)
            ,@(map (lambda (binding) (ir->sexp (cadr binding))) bindings)))))

    ((ir-quote? ir) `(quote ,(ir-quote-datum ir)))

    ((ir-begin? ir) `(begin ,@(map ir->sexp (ir-begin-exps ir))))

    ((ir-void? ir) #f)

    ((ir-define? ir)
      (let ((var (ir-define-var ir)))
        `(define ,(variable-name var) ,(ir->sexp (ir-define-exp ir)))))
    ((and (vector? ir) (eq? 'primcall (vector-ref ir 0)))
      `(primcall ,(vector-ref ir 1) ,@(map ir->sexp (vector-ref ir 2))))
    ((and (vector? ir)
          (>= (vector-length ir) 2)
          (symbol? (vector-ref ir 0))
          (memq (vector-ref ir 0)
                '(app if ref set! lambda case-lambda letrec* loop let quote begin void define
                      primcall)))
      (let ((elts (vector->list ir)))
        (list->sexp (reverse (cdr (reverse elts))))))
    ((vector? ir)
      (let ((elts (vector->list ir)))
        (if (and (pair? elts) (symbol? (car elts)))
            (list->sexp elts)
            (list->vector (map ir->sexp elts)))))
    ((pair? ir)
      (list->sexp ir))

    ;; Not an IR record - pass through (for symbols, numbers, etc.)
    (else ir)))

;; Helper to format annotation info - returns list for splicing
(define (pp-ann ann)
  (if ann
      (list (string->symbol (string-append "@"
                                           (number->string (annotation-start ann))
                                           ":"
                                           (number->string (annotation-len ann)))))
      '()))

;; Helper to pretty-print a variable
(define (pp-atom->string x)
  (cond
    ((symbol? x) (symbol->string x))
    ((number? x) (number->string x))
    ((string? x) x)
    (else "#<obj>")))

(define (pp-var v)
  (if (variable? v)
      (string->symbol (string-append "#<var "
                                     (pp-atom->string (variable-name v))
                                     (if (variable-assigned v) " assigned" "")
                                     (let ((lib (variable-library-name v)))
                                       (if lib
                                           (string-append " "
                                                          (if (list? lib)
                                                              (apply string-append
                                                                     (map (lambda (x)
                                                                            (string-append (pp-atom->string x)
                                                                                           " "))
                                                                          lib))
                                                              (pp-atom->string lib)))
                                           ""))
                                     ">"))
      v))

;; Helper to pretty-print variable list (handles improper lists)
(define (pp-vars vars)
  (cond
    ((null? vars) '())
    ((pair? vars) (cons (pp-var (car vars)) (pp-vars (cdr vars))))
    (else (pp-var vars))))

;; Pretty-printer: displays IR records in a readable format
(define (ir-pp ir)
  (cond
    ((ir-application? ir)
      `(APP ,@(pp-ann (ir-application-ann ir))
            ,@(if (ir-application-well-known ir) '(WELL-KNOWN) '())
            ,(ir-pp (ir-application-fun ir))
            ,@(map ir-pp (ir-application-args ir))))

    ((ir-conditional? ir)
      (let ((else-part (ir-conditional-else ir)))
        (if else-part
            `(IF ,@(pp-ann (ir-conditional-ann ir))
                 ,(ir-pp (ir-conditional-test ir))
                 ,(ir-pp (ir-conditional-then ir))
                 ,(ir-pp (ir-conditional-else ir)))
            `(IF ,@(pp-ann (ir-conditional-ann ir))
                 ,(ir-pp (ir-conditional-test ir))
                 ,(ir-pp (ir-conditional-then ir))))))

    ((ir-reference? ir)
      (let ((var (ir-reference-var ir))
            (global? (ir-reference-global? ir))
            (mutable? (ir-reference-mutable? ir)))
        (if global?
            (if mutable?
                `(GLOBAL-REF/MUT ,@(pp-ann (ir-reference-ann ir)) ,(pp-var var))
                `(GLOBAL-REF/IMMUT ,@(pp-ann (ir-reference-ann ir)) ,(pp-var var)))
            (if mutable?
                `(LEXICAL-REF/MUT ,@(pp-ann (ir-reference-ann ir)) ,(pp-var var))
                `(LEXICAL-REF/IMMUT ,@(pp-ann (ir-reference-ann ir)) ,(pp-var var))))))

    ((ir-assignment? ir)
      (let ((var (ir-assignment-var ir)) (global? (ir-assignment-global? ir)))
        `(,(if global? 'GLOBAL-SET! 'LEXICAL-SET!)
          ,@(pp-ann (ir-assignment-ann ir))
          ,(pp-var var)
          ,(ir-pp (ir-assignment-exp ir)))))

    ((ir-lambda? ir)
      `(LAMBDA ,@(pp-ann (ir-lambda-ann ir))
               ,@(if (ir-lambda-well-known ir) '(WELL-KNOWN) '())
               ,@(if (null? (ir-lambda-freevars ir))
                     '()
                     (list `(FREEVARS ,@(pp-vars (ir-lambda-freevars ir)))))
               ,@(map (lambda (clause)
                        (list (pp-vars (car clause)) (ir-pp (cadr clause))))
                      (ir-lambda-cases ir))))

    ((ir-let? ir)
      `(LET ,@(pp-ann (ir-let-ann ir))
            ,@(map (lambda (binding)
                     (list (pp-var (car binding)) (ir-pp (cadr binding))))
                   (ir-let-bindings ir))
            ,(ir-pp (ir-let-body ir))))

    ((ir-letrec*? ir)
      (let ((bindings (ir-letrec*-bindings ir)))
        `(LETREC* ,@(pp-ann (ir-letrec*-ann ir))
                  ,(if (and (pair? bindings) (letrec*-binding-group? (car bindings)))
                       (map (lambda (group)
                              (map (lambda (binding)
                                     (list (pp-var (car binding)) (ir-pp (cadr binding))))
                                   group))
                            bindings)
                       (map (lambda (binding)
                              (list (pp-var (car binding)) (ir-pp (cadr binding))))
                            bindings))
                  ,(ir-pp (ir-letrec*-body ir)))))

    ((ir-loop? ir)
      `(LOOP ,@(pp-ann (ir-loop-ann ir))
             ,(pp-var (ir-loop-name ir))
             ,(map (lambda (binding)
                     (list (pp-var (car binding)) (ir-pp (cadr binding))))
                   (ir-loop-args ir))
             ,(ir-pp (ir-loop-body ir))))

    ((ir-quote? ir) `(QUOTE ,@(pp-ann (ir-quote-ann ir)) ,(ir-quote-datum ir)))

    ((ir-begin? ir)
      `(BEGIN ,@(pp-ann (ir-begin-ann ir)) ,@(map ir-pp (ir-begin-exps ir))))

    ((ir-void? ir) `(VOID ,@(pp-ann (ir-void-ann ir))))

    ((ir-define? ir)
      `(DEFINE ,@(pp-ann (ir-define-ann ir))
               ,(pp-var (ir-define-var ir))
               ,(ir-pp (ir-define-exp ir))))

    ((ir-primcall? ir)
      `(PRIMCALL ,@(pp-ann (ir-primcall-ann ir))
                 ,(ir-primcall-name ir)
                 ,@(map ir-pp (ir-primcall-args ir))))

    ;; Not an IR record - pass through (for symbols, numbers, etc.)
    (else ir)))
