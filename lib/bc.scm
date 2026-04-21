;; Bytecode generator for hawk

(include "opcodes.scm")
(include "memory_layout.scm")
(include "fix-letrec.scm")

(define-syntax ->
   (syntax-rules ()
     ((_ arg (command args ...) rest ...) (-> (command arg args ...) rest ...))
     ((_ arg command rest ...) (-> (command arg) rest ...))
     ((_ arg) arg)))

(define-syntax and-let
   (syntax-rules ()
     ((_ ()) #t)
     ((and-let () form form* ...) (begin form form* ...))
     ((_ ((id expr))) expr)
     ((_ ((expr))) expr)
     ((_ (id)) id)
     ((_ ((id expr) . claw*) . body)
      (let ((id expr)) (and id (and-let claw* . body))))
     ((_ ((expr) . claw*) . body) (and expr (and-let claw* . body)))
     ((_ (id . claw*) . body) (and id (and-let claw* . body)))
     ((_ . _) (syntax-error "ill-formed and-let form"))))

;; Temporary fallback until the new expander exposes annotation records.
(define (annotation? _) #f)

;; Integer-only arithmetic-shift replacement for bootstrap.
(define (arithmetic-shift x k)
  (cond
    ((= k 0) x)
    ((> k 0) (* x (expt 2 k)))
    (else
      (let ((d (expt 2 (- k))))
        (if (>= x 0) (quotient x d) (- (quotient (+ (- x) (- d 1)) d)))))))

(define primcalls
  '((+ . ADD)
    (- . SUB)
    (* . MUL)
    (/ . DIV)
    (quotient . QUOTIENT)
    (truncate-quotient . QUOTIENT)
    (exact . EXACT)
    (truncate . TRUNCATE)
    (inexact . INEXACT)
    (exact->inexact . INEXACT)
    (inexact->exact . EXACT)
    (char->integer . CHAR_INTEGER)
    (integer->char . INTEGER_CHAR)
    (values . VALUES)
    (call-with-values . CALL_WITH_VALUES)
    (< . LT)
    (> . GT)
    (eq? . EQ)
    (= . EQV)
    (>= . GTE)
    (<= . LTE)
    ;(display . WRITE)
  ))
(define (primcall-arity name)
  (cond
    ((eq? name 'values) 'any)
    ((eq? name 'call-with-values) 2)
    ((memq name '(- / + * < > = >= <= quotient truncate-quotient remainder modulo))
      2)
    ((memq name
           '(exact->inexact inexact->exact char->integer integer->char display))
      1)
    (else #f)))
(define (variable-full-name var)
  (let ((name (variable-name var)) (lib (variable-library-name var)))
    (if (or (eq? lib #f) (equal? lib ""))
        name
        (string->symbol (string-append (if (pair? lib)
                                           (library-spec->normalized-string lib)
                                           (if (symbol? lib) (symbol->string lib) lib))
                                       ":"
                                       (symbol->string name))))))

(define empty-library-name (string->symbol ""))

(define (global-values-var? var)
  (let ((lib (variable-library-name var)))
    (and (eq? (variable-name var) 'values)
         (or (eq? lib #f) (equal? lib "") (eq? lib empty-library-name)))))

;; List-backed eq? table for bootstrap/runtime gaps.
(define custom_hash_table_tag (cons #f #f))
(define (make_custom_hash_table) (cons custom_hash_table_tag '()))
(define (custom_hash_table? table)
  (and (pair? table) (eq? (car table) custom_hash_table_tag)))
(define (custom_hash_table_ref table key)
  (cond
    ((assq key (cdr table)) => cdr)
    (else (error "custom-hash-table-ref: no value associated with" key))))
(define (custom_hash_table_ref/default table key default)
  (let ((entry (assq key (cdr table)))) (if entry (cdr entry) default)))
(define (custom_hash_table_set! table key value)
  (let ((entry (assq key (cdr table))))
    (if entry
        (set-cdr! entry value)
        (set-cdr! table (cons (cons key value) (cdr table))))))
(define (custom_hash_table_delete! table key)
  (let loop ((prev table) (cur (cdr table)))
    (cond
      ((null? cur) #f)
      ((eq? (caar cur) key) (set-cdr! prev (cdr cur)) #t)
      (else (loop cur (cdr cur))))))
(define (custom_hash_table_exists? table key) (and (assq key (cdr table)) #t))
(define (custom_hash_table_size table) (length (cdr table)))
(define (custom_hash_table_keys table) (map car (cdr table)))
(define (custom_hash_table_merge! table table2)
  (for-each (lambda (entry) (custom_hash_table_set! table (car entry) (cdr entry)))
            (cdr table2))
  table)

;; Inlines primitives
(define (simple-pass ir)
  (cond
    ((and (ir-application? ir)
          (ir-reference? (ir-application-fun ir))
          (variable? (ir-reference-var (ir-application-fun ir))))
      (let* ((fun (ir-application-fun ir))
             (var (ir-reference-var fun))
             (name (variable-name var))
             (lib (variable-library-name var))
             (args (ir-application-args ir))
             (ann (ir-reference-ann fun)))
        (cond
          ((equal? lib '(hawk sys)) (build-primcall name (map simple-pass args) ann))
          ((and (equal? lib "") (eq? name '-) (= (length args) 1))
            (build-primcall 'SUB (list (build-quote 0 ann) (simple-pass (car args))) ann))
          ((and (equal? lib "") (eq? name '/) (= (length args) 1))
            (build-primcall 'DIV (list (build-quote 1 ann) (simple-pass (car args))) ann))
          ((and (equal? lib "")
                (assq name primcalls)
                (let ((arity (primcall-arity name)) (nargs (length args)))
                  (or (eq? arity 'any) (and arity (= nargs arity)))))
            (build-primcall (cdr (assq name primcalls)) (map simple-pass args) ann))
          (else (walk-ir ir simple-pass)))))
    (else (walk-ir ir simple-pass))))

;; TODO: more performant boxing: remember we must store/zero all fields before another alloc.
(define (assignment-conversion ir)
  (define (boxed-load box ann)
    (build-primcall 'LOAD
                    `(,(build-lexical-reference (cdr box) #t #f) ,(build-quote 0 ann))
                    ann))

  (define (boxed-store box value ann)
    (build-primcall 'STORE
                    `(,(build-lexical-reference (cdr box) #t #f) ,value ,(build-quote 0 ann))
                    ann))

  (define (alloc-box ann)
    (build-primcall 'ALLOC `(,(build-quote 24 ann) ,(build-quote 3 ann)) ann))

  (define (init-box-body box body ann)
    (build-begin `(,(build-primcall 'STORE
                                    `(,(build-lexical-reference (cdr box) #t #f)
                                      ,(build-lexical-reference (car box) #t #f)
                                      ,(build-quote 0 ann))
                                    ann)
                   ,(build-primcall 'STORE
                                    `(,(build-lexical-reference (cdr box) #t #f)
                                      ,(build-quote 0 ann)
                                      ,(build-quote 1 ann))
                                    ann)
                   ,body)
                 ann))

  (define (wrap-boxes new-boxes body ann)
    (fold-right (lambda (box acc)
                  (build-let `((,(cdr box) ,(alloc-box ann))) (init-box-body box acc ann) ann))
                body
                new-boxes))

  (define (convert expr boxes)
    (cond
      ((ir-reference? expr)
        (let ((var (ir-reference-var expr)) (ann (ir-reference-ann expr)))
          (cond ((assq var boxes) => (lambda (box) (boxed-load box ann))) (else expr))))

      ((ir-assignment? expr)
        (let* ((var (ir-assignment-var expr))
               (exp (ir-assignment-exp expr))
               (global? (ir-assignment-global? expr))
               (ann (ir-assignment-ann expr))
               (new-exp (convert exp boxes)))
          (cond
            ((assq var boxes) => (lambda (box) (boxed-store box new-exp ann)))
            (else (build-set var new-exp global? ann)))))

      ((ir-lambda? expr)
        (let* ((cases (ir-lambda-cases expr))
               (ann (ir-lambda-ann expr))
               (new-cases
                  (map (lambda (clause)
                         (let* ((args (car clause))
                                (body (cadr clause))
                                (arg-list (to-proper args))
                                (boxed-args (filter variable-assigned arg-list))
                                (new-boxes
                                   (map (lambda (v)
                                          (cons v
                                                (build-variable (string->symbol (string-append "boxed-"
                                                                                               (symbol->string (variable-name v))))
                                                                #f)))
                                        boxed-args))
                                (new-body (convert body (append new-boxes boxes)))
                                (boxed-body
                                   (if (null? new-boxes)
                                       new-body
                                       (wrap-boxes new-boxes new-body ann))))
                           `(,args ,boxed-body)))
                       cases)))
          (build-lambda new-cases ann)))

      (else (walk-ir expr (lambda (child) (convert child boxes))))))

  (convert ir '()))

(define (recover-let ir)
  (or (and-let ((fun (and (ir-application? ir) (ir-application-fun ir)))
                (cases (and (ir-lambda? fun) (ir-lambda-cases fun)))
                ((= (length cases) 1))
                (clause (car cases))
                (args (car clause))
                (body (cadr clause))
                (params (ir-application-args ir))
                ((list? params)) ;; TODO: the rest-args cases
                ((list? args))
                ((= (length args) (length params))))
               (let ((lambda-ann (ir-lambda-ann fun)))
                 (build-let (map list args (map recover-let params))
                            (recover-let body)
                            lambda-ann)))
     (walk-ir ir recover-let)))

;; adds name field to lambdas.
(define (name-lambdas ir)
  (define (var-name var) (symbol->string (variable-name var)))
  (define (binding-lambda-name cur var) (string-append cur "-" (var-name var)))
  (define (name-lambdas-int ir cur)
    (define (name-cases cases name)
      (map (lambda (clause) `(,(car clause) ,(name-lambdas-int (cadr clause) name)))
           cases))
    (define (named-lambda cases name ann)
      (build-lambda (name-cases cases name) name '() ann))
    (define (rewrite-letrec* ir)
      (let* ((bindings (ir-letrec*-bindings ir))
             (new-bindings
                (map (lambda (binding)
                       (let ((var (car binding)) (init (cadr binding)) (ann (caddr binding)))
                         `(,var ,(if (ir-lambda? init)
                                     (named-lambda (ir-lambda-cases init)
                                                   (binding-lambda-name cur var)
                                                   (ir-lambda-ann init))
                                     (name-lambdas-int init cur))
                                ,ann)))
                     bindings)))
        (build-letrec* new-bindings
                       (name-lambdas-int (ir-letrec*-body ir) cur)
                       (ir-letrec*-ann ir))))
    (define (rewrite-define ir)
      (and-let ((var (and (ir-define? ir) (ir-define-var ir)))
                (exp (ir-define-exp ir))
                (cases (and (ir-lambda? exp) (ir-lambda-cases exp))))
               (let ((lam-ann (ir-lambda-ann exp))
                     (define-ann (ir-define-ann ir))
                     (name (var-name var)))
                 (build-define var (named-lambda cases name lam-ann) define-ann))))
    (define (rewrite-lambda ir)
      (and-let ((cases (and (ir-lambda? ir) (ir-lambda-cases ir))))
               (let ((lam-ann (ir-lambda-ann ir)))
                 (named-lambda cases (string-append cur "-anon") lam-ann))))
    (define (name-pass ir)
      (or (rewrite-define ir)
         (and (ir-letrec*? ir) (rewrite-letrec* ir))
         (rewrite-lambda ir)
         (walk-ir ir name-pass)))
    (name-pass ir))
  (name-lambdas-int ir "REPL"))

;; Add  fix (i.e. letrec*) to all.
(define (fix-all ir)
  (define (rewrite-cases cases)
    (map (lambda (clause) `(,(car clause) ,(fix-all (cadr clause)))) cases))
  (cond
    ((ir-letrec*? ir)
      (let ((bindings (ir-letrec*-bindings ir)))
        (for binding bindings
          (let ((init (cadr binding)))
            (set-ir-lambda-cases! init (rewrite-cases (ir-lambda-cases init)))))
        (set-ir-letrec*-body! ir (fix-all (ir-letrec*-body ir)))
        ir))
    ((and (ir-lambda? ir) (ir-lambda-name ir))
      (let* ((name (ir-lambda-name ir))
             (ann (ir-lambda-ann ir))
             (tmp (build-variable (string->symbol name) #f)))
        (set-ir-lambda-cases! ir (rewrite-cases (ir-lambda-cases ir)))
        (build-letrec* `((,tmp ,ir #f)) (build-lexical-reference tmp #f #f) #f)))
    (else (walk-ir ir fix-all))))

(define (print-combining-bindings groups)
  (display "combining-bindings ")
  (write (map (lambda (group) (map variable-name group)) groups))
  (newline))

(define (escape-analyze ir)
  (let ((bound (make_custom_hash_table)))
    (define (mark-escaped! var)
      (when (custom_hash_table_exists? bound var)
        (let ((escapes (custom_hash_table_ref bound var)))
          (custom_hash_table_set! escapes var #t))))
    (define (pass ir)
      (cond
        ((ir-reference? ir) (mark-escaped! (ir-reference-var ir)) ir)
        ((ir-application? ir)
          (let ((fun (ir-application-fun ir)))
            ;; Direct calls are where we'll later rewrite to label-calls.
            (if (and (ir-reference? fun)
                     (custom_hash_table_exists? bound (ir-reference-var fun)))
                (set-ir-application-well-known! ir #t)
                (pass fun))
            (for-each pass (ir-application-args ir))
            ir))
        ((ir-letrec*? ir)
          (let* ((bindings (ir-letrec*-bindings ir))
                 (vars (map car bindings))
                 (escapes (make_custom_hash_table)))
            (for-each (lambda (var)
                        (custom_hash_table_set! escapes var #f)
                        (custom_hash_table_set! bound var escapes))
                      vars)
            (for-each (lambda (binding) (pass (cadr binding))) bindings)
            (pass (ir-letrec*-body ir))
            (let* ((not-well-known
                      (filter (lambda (binding) (custom_hash_table_ref escapes (car binding)))
                              bindings))
                   (well-known
                      (filter (lambda (binding) (not (custom_hash_table_ref escapes (car binding))))
                              bindings))
                   (groups
                      (if (null? not-well-known)
                          (list bindings)
                          (cons (append (list (car not-well-known)) well-known)
                                (map list (cdr not-well-known))))))
              (for-each (lambda (binding)
                          (let ((var (car binding)) (init (cadr binding)))
                            (when (and (ir-lambda? init) (not (custom_hash_table_ref escapes var)))
                              (set-ir-lambda-well-known! init #t))))
                        bindings)
              (set-ir-letrec*-bindings! ir groups))
            (for-each (lambda (var) (custom_hash_table_delete! bound var)) vars)
            ir))
        (else (walk-ir ir pass))))
    (pass ir)))

(define (lower-loops ir)
  (define (grouped-bindings? bindings)
    (and (pair? bindings) (pair? (car bindings)) (pair? (caar bindings))))

  (define (binding-groups bindings)
    (cond
      ((null? bindings) '())
      ((grouped-bindings? bindings) bindings)
      (else (list bindings))))

  (define (flatten-binding-groups groups)
    (if (null? groups) '() (apply append groups)))

  (define (single-letrec-binding bindings)
    (let ((flat (flatten-binding-groups (binding-groups bindings))))
      (and (= (length flat) 1) (car flat))))

  (define (tailcall? ir var)
    (and (ir-application? ir)
         (ir-reference? (ir-application-fun ir))
         (eq? var (ir-reference-var (ir-application-fun ir)))))

  (define (only-tailcalls? var ir)
    (define loop-ok? #t)
    (define (walk-letrec ir body-walk)
      (for-each (lambda (group)
                  (for-each (lambda (binding) (walk-nontail (cadr binding))) group))
                (binding-groups (ir-letrec*-bindings ir)))
      (body-walk (ir-letrec*-body ir))
      ir)
    (define (walk-nontail ir)
      (cond
        ((ir-reference? ir)
          (when (eq? var (ir-reference-var ir)) (set! loop-ok? #f))
          ir)
        ((tailcall? ir var)
          (set! loop-ok? #f)
          (for-each walk-nontail (ir-application-args ir))
          ir)
        ((ir-letrec*? ir) (walk-letrec ir walk-nontail))
        (else (walk-ir ir walk-nontail))))
    (define (walk-tail ir)
      (cond
        ((ir-conditional? ir)
          (walk-nontail (ir-conditional-test ir))
          (walk-tail (ir-conditional-then ir))
          (walk-tail (ir-conditional-else ir))
          ir)
        ((ir-let? ir)
          (for-each (lambda (binding) (walk-nontail (cadr binding)))
                    (ir-let-bindings ir))
          (walk-tail (ir-let-body ir))
          ir)
        ((ir-letrec*? ir) (walk-letrec ir walk-tail))
        ((ir-begin? ir)
          (let ((exps (ir-begin-exps ir)))
            (unless (null? exps)
              (for-each walk-nontail (reverse (cdr (reverse exps))))
              (walk-tail (car (reverse exps)))))
          ir)
        ((tailcall? ir var)
          (for-each walk-nontail (ir-application-args ir))
          ir)
        (else (walk-nontail ir))))
    (walk-tail ir)
    loop-ok?)

  (define (loop-bindings vars args) (map list (to-proper vars) args))

  (define (pass ir)
    (cond
      ((ir-letrec*? ir)
        (let* ((bindings (ir-letrec*-bindings ir))
               (binding (single-letrec-binding bindings))
               (body (ir-letrec*-body ir)))
          (or (and binding
                   (let ((var (car binding))
                         (init (cadr binding))
                         (ann (or (caddr binding) (ir-letrec*-ann ir))))
                     (and (ir-lambda? init)
                          (= (length (ir-lambda-cases init)) 1)
                          (ir-lambda-well-known init)
                          (ir-application? body)
                          (ir-reference? (ir-application-fun body))
                          (eq? var (ir-reference-var (ir-application-fun body)))
                          (let* ((clause (car (ir-lambda-cases init)))
                                 (vars (car clause))
                                 (lam-body (cadr clause))
                                 (args (ir-application-args body)))
                            (and (list? vars)
                                 (list? args)
                                 (= (length vars) (length args))
                                 (only-tailcalls? var lam-body)
                                 (build-loop (loop-bindings vars (map pass args))
                                             (pass lam-body)
                                             var
                                             ann))))))
             (begin
               (for-each (lambda (group)
                           (for-each (lambda (binding)
                                       (set-car! (cdr binding) (pass (cadr binding))))
                                     group))
                         (binding-groups bindings))
               (set-ir-letrec*-body! ir (pass body))
               ir))))
      (else (walk-ir ir pass))))
  (pass ir))

(define (required-free-vars ir)
  (define (grouped-bindings? bindings)
    (and (pair? bindings) (pair? (car bindings)) (pair? (caar bindings))))

  (define (binding-groups bindings)
    (cond
      ((null? bindings) '())
      ((grouped-bindings? bindings) bindings)
      (else (list bindings))))

  (define (flatten-binding-groups groups)
    (if (null? groups) '() (apply append groups)))

  (define (ordered-add item items)
    (if (memq item items) items (append items (list item))))

  (define (all-empty? lists)
    (or (null? lists) (and (null? (car lists)) (all-empty? (cdr lists)))))

  (define (rho-ref rho var) (cond ((assq var rho) => cdr) (else var)))

  (define (canonicalize rho value)
    (let loop ((value value) (seen '()))
      (cond
        ((not (variable? value)) value)
        ((memq value seen) value)
        (else
          (let ((next (rho-ref rho value)))
            (if (eq? next value) value (loop next (cons value seen))))))))

  (define (extend-rho rho bindings) (append bindings rho))

  (define (extend-rho-self rho vars)
    (extend-rho rho (map (lambda (var) (cons var var)) vars)))

  (define (closure-ref-expr clo num)
    (build-primcall 'closure-ref
                    `(,(build-lexical-reference clo #t #f) ,(build-quote num #f))
                    #f))

  (define (closure-set-expr clo num value)
    (build-primcall 'closure-set!
                    `(,(build-lexical-reference clo #t #f) ,(build-quote num #f) ,value)
                    #f))

  (define label-cache (make_custom_hash_table))
  (define lambda-bindings (make_custom_hash_table))
  (define lambda-self-vars (make_custom_hash_table))
  (define lambda-rep-vars (make_custom_hash_table))
  (define (label-var var)
    (or (custom_hash_table_ref/default label-cache var #f)
       (let ((label
                (build-variable (string->symbol (string-append (symbol->string (variable-name var))
                                                               "-label"))
                                #f)))
         (custom_hash_table_set! label-cache var label)
         label)))

  (define (label-name var) (variable-name (label-var var)))

  (define (lambda-freevar-rho ir cp freevars)
    (cond
      ((not cp) '())
      ((and (ir-lambda-well-known ir) (pair? freevars) (null? (cdr freevars)))
        (list (cons (car freevars) cp)))
      (else
        (map (lambda (fv num) (cons fv (closure-ref-expr cp num)))
             freevars
             (iota (length freevars) 1)))))

  (define (binding-alias-value binding rho)
    (let ((init (cadr binding)))
      (cond
        ((and (ir-reference? init) (not (ir-reference-global? init)))
          (canonicalize rho (ir-reference-var init)))
        ((ir-quote? init) (ir-quote-datum init))
        (else (car binding)))))

  (define (let-body-rho bindings rho)
    (extend-rho rho
                (map (lambda (binding) (cons (car binding) (binding-alias-value binding rho)))
                     bindings)))

  (define (group-rep group) (car (car group)))

  (define (group-first-lambda group) (cadr (car group)))

  (define (choose-representation group final-set)
    (let ((first (group-first-lambda group)) (rep (group-rep group)))
      (cond
        ((ir-lambda-well-known first)
          (cond
            ((null? final-set) #f)
            ((null? (cdr final-set)) (car final-set))
            (else rep)))
        ((null? final-set) (make-const-closure (label-var rep)))
        (else rep))))

  (define (group-needs-closure? group final-set)
    (let ((first (group-first-lambda group)))
      (cond
        ((null? final-set) (not (ir-lambda-well-known first)))
        ((ir-lambda-well-known first) (not (null? (cdr final-set))))
        (else #t))))

  (define (lambda-needs-cp? ir)
    (or (not (ir-lambda-well-known ir)) (not (null? (ir-lambda-freevars ir)))))

  (define (group-local-refs group letrec-vars)
    (let loop-groups ((bindings group) (acc '()))
      (if (null? bindings)
          acc
          (let loop-fvs ((fvs (ir-lambda-freevars (cadr (car bindings)))) (acc acc))
            (if (null? fvs)
                (loop-groups (cdr bindings) acc)
                (loop-fvs (cdr fvs)
                          (if (memq (car fvs) letrec-vars) (ordered-add (car fvs) acc) acc)))))))

  (define (group-mentioned? group refs)
    (let loop ((bindings group))
      (and (pair? bindings)
           (or (memq (car (car bindings)) refs) (loop (cdr bindings))))))

  (define (group-initial-required group letrec-vars rho)
    (let loop-groups ((bindings group) (acc '()))
      (if (null? bindings)
          acc
          (let loop-fvs ((fvs (ir-lambda-freevars (cadr (car bindings)))) (acc acc))
            (if (null? fvs)
                (loop-groups (cdr bindings) acc)
                (let ((fv (car fvs)))
                  (loop-fvs (cdr fvs)
                            (if (memq fv letrec-vars)
                                acc
                                (let ((value (canonicalize rho fv)))
                                  (cond
                                    ((variable? value) (ordered-add value acc))
                                    ((and (ir-primcall? value)
                                          (eq? (ir-primcall-name value) 'closure-ref))
                                      (ordered-add fv acc))
                                    (else acc)))))))))))

  (define (final-required-sets groups initial-sets local-refs)
    (if (all-empty? initial-sets)
        (map (lambda (_) '()) groups)
        (map (lambda (group init refs)
               (let ((self-rep (group-rep group)))
                 (let loop ((rest-groups groups) (acc init))
                   (if (null? rest-groups)
                       acc
                       (let ((rep (group-rep (car rest-groups))))
                         (loop (cdr rest-groups)
                               (if (or (eq? rep self-rep)
                                      (not (group-mentioned? (car rest-groups) refs)))
                                   acc
                                   (ordered-add rep acc))))))))
             groups
             initial-sets
             local-refs)))

  (define (letrec-body-rho rho groups final-sets)
    (extend-rho rho
                (apply append
                       (map (lambda (group final-set)
                              (let ((value (choose-representation group final-set)))
                                (map (lambda (binding) (cons (car binding) value)) group)))
                            groups
                            final-sets))))

  (define (pass ir rho)
    (cond
      ((ir-reference? ir)
        (if (ir-reference-global? ir)
            ir
            (let ((var (ir-reference-var ir))
                  (ann (ir-reference-ann ir))
                  (mutable? (ir-reference-mutable? ir)))
              (let ((value (canonicalize rho var)))
                (cond
                  ((eq? value var) ir)
                  ((variable? value) (build-lexical-reference value mutable? ann))
                  ((and (ir-primcall? value) (eq? (ir-primcall-name value) 'closure-ref)) value)
                  (else (build-quote value ann)))))))
      ((ir-loop? ir)
        (let* ((bindings (ir-loop-args ir))
               (vars (map car bindings))
               (body-rho (extend-rho-self rho (cons (ir-loop-name ir) vars))))
          (for-each (lambda (binding) (set-car! (cdr binding) (pass (cadr binding) rho)))
                    bindings)
          (set-ir-loop-body! ir (pass (ir-loop-body ir) body-rho))
          ir))
      ((ir-let? ir)
        (let* ((bindings (ir-let-bindings ir)) (body-rho (let-body-rho bindings rho)))
          (for-each (lambda (binding) (set-car! (cdr binding) (pass (cadr binding) rho)))
                    bindings)
          (vector-set! ir 2 (pass (ir-let-body ir) body-rho))
          ir))
      ((ir-application? ir)
        (let* ((fun (ir-application-fun ir))
               (fun* (pass fun rho))
               (args* (map (lambda (arg) (pass arg rho)) (ir-application-args ir)))
               (ann (ir-application-ann ir)))
          (when (and (ir-application-well-known ir)
                     (ir-reference? fun)
                     (not (ir-reference-global? fun)))
            (let ((target
                     (custom_hash_table_ref/default lambda-bindings (ir-reference-var fun) #f)))
              (when target
                (when (lambda-needs-cp? target)
                  (unless (and (ir-quote? fun*) (eq? (ir-quote-datum fun*) #f))
                    (set! args* (cons fun* args*))))
                (set! fun*
                  (build-lexical-reference (label-var (ir-reference-var fun)) #f ann)))))
          (set-ir-application-fun! ir fun*)
          (set-ir-application-args! ir args*)
          ir))
      ((ir-lambda? ir)
        (let* ((needs-cp (lambda-needs-cp? ir))
               (cp (and needs-cp (build-variable 'cp #f)))
               (self (custom_hash_table_ref/default lambda-self-vars ir #f))
               (rep (custom_hash_table_ref/default lambda-rep-vars ir #f))
               (freevars (ir-lambda-freevars ir))
               (lambda-rho
                  (extend-rho rho
                              (append (if (and cp self) (list (cons self cp)) '())
                                      (if (and cp rep (not (eq? rep self)))
                                          (list (cons rep cp))
                                          '())
                                      (lambda-freevar-rho ir cp freevars)))))
          (set-ir-lambda-cases! ir
                                (map (lambda (clause)
                                       (let* ((args (car clause))
                                              (body (cadr clause))
                                              (args* (if needs-cp (cons cp args) args)))
                                         `(,args* ,(pass body
                                                         (extend-rho-self lambda-rho
                                                                          (to-proper args*))))))
                                     (ir-lambda-cases ir))))
        ir)
      ((ir-letrec*? ir)
        (let* ((groups (ir-letrec*-bindings ir))
               (bindings (apply append groups)) ;; flatten groups, all bindings.
               (vars (map car bindings)) ;; variables bound by this letrec.
               (initial-sets ;; Just all freevars after canonicalization (removing alias+constants)
                  (map (lambda (group) (group-initial-required group vars rho)) groups))
               (local-refs (map (lambda (group) (group-local-refs group vars)) groups))
               (final-sets (final-required-sets groups initial-sets local-refs))
               (group-values
                  (map (lambda (group final-set) (choose-representation group final-set))
                       groups
                       final-sets))
               (body-rho (letrec-body-rho rho groups final-sets)))
          (for-each (lambda (group final-set)
                      (for-each (lambda (binding)
                                  (let ((init (cadr binding)))
                                    (when (ir-lambda? init)
                                      (custom_hash_table_set! lambda-bindings (car binding) init)
                                      (custom_hash_table_set! lambda-self-vars init (car binding))
                                      (let ((rep (group-rep group)))
                                        (when (variable? rep)
                                          (custom_hash_table_set! lambda-rep-vars init rep)))
                                      (set-ir-lambda-freevars! init final-set))))
                                group))
                    groups
                    final-sets)
          (for-each (lambda (group)
                      (for-each (lambda (binding)
                                  (set-car! (cdr binding) (pass (cadr binding) body-rho)))
                                group))
                    groups)
          (let* ((label-bindings
                    (map (lambda (binding)
                           (let ((var (car binding)) (init (cadr binding)) (lrann (caddr binding)))
                             `(,(label-var var) ,init ,lrann)))
                         bindings))
                 (closure-bindings
                    (filter-map (lambda (group value final-set)
                                  (and (group-needs-closure? group final-set)
                                       (variable? value)
                                       `(,value ,(build-primcall 'closure
                                                                 (list (build-quote (length final-set)
                                                                                    #f)
                                                                       (build-quote (label-name (car (car group)))
                                                                                    #f))
                                                                 #f))))
                                groups
                                group-values
                                final-sets))
                 (init-sets
                    (apply append
                           (map (lambda (group value final-set)
                                  (if (and (group-needs-closure? group final-set) (variable? value))
                                      (map (lambda (fv num)
                                             (closure-set-expr value
                                                               num
                                                               (pass (build-lexical-reference fv
                                                                                              #t
                                                                                              #f)
                                                                     body-rho)))
                                           final-set
                                           (iota (length final-set) 1))
                                      '()))
                                groups
                                group-values
                                final-sets)))
                 (body (pass (ir-letrec*-body ir) body-rho))
                 (body*
                    (if (null? closure-bindings)
                        body
                        (build-let closure-bindings
                                   (build-begin `(,@init-sets ,body) #f)
                                   (ir-letrec*-ann ir)))))
            (for-each (lambda (var) (custom_hash_table_delete! lambda-bindings var)) vars)
            (build-letrec* label-bindings body* (ir-letrec*-ann ir)))))
      (else (walk-ir ir (lambda (child) (pass child rho))))))
  (pass ir '()))

(define (uncover-free ir)
  (let uncover-free ((ir ir) (bindings '()) (fv-info (make_custom_hash_table)))
    (define (pass ir)
      (cond
        ((ir-reference? ir)
          (let ((var (ir-reference-var ir)))
            (when (memq var bindings) (custom_hash_table_set! fv-info var #t))
            ir))
        ((ir-let? ir)
          (let* ((old-bindings (ir-let-bindings ir))
                 (vars (map car old-bindings))
                 (new-bindings (map (lambda (b) `(,(car b) ,(pass (cadr b)))) old-bindings))
                 (new-body (uncover-free (ir-let-body ir) (append vars bindings) fv-info)))
            (for key vars (custom_hash_table_delete! fv-info key))
            (build-let new-bindings new-body (ir-let-ann ir))))
        ((ir-letrec*? ir)
          (let* ((old-bindings (ir-letrec*-bindings ir))
                 (vars (map car old-bindings))
                 (inits (map cadr old-bindings))
                 (lranns (map caddr old-bindings))
                 (names (map ir-lambda-name inits))
                 (cases-list (map ir-lambda-cases inits))
                 (lanns (map ir-lambda-ann inits))
                 (new-env (append vars bindings))
                 (infos (map (lambda (_) (make_custom_hash_table)) vars))
                 (new-cases
                    (map (lambda (cases info)
                           (map (lambda (clause)
                                  (let ((args (car clause)) (lbody (cadr clause)))
                                    `(,args ,(uncover-free lbody
                                                           (append (to-proper args) new-env)
                                                           info))))
                                cases))
                         cases-list
                         infos))
                 (new-body (uncover-free (ir-letrec*-body ir) new-env fv-info))
                 (free-vars
                    (map (lambda (cases table)
                           (for clause cases
                             (for key (to-proper (car clause))
                               (custom_hash_table_delete! table key)))
                           (custom_hash_table_keys table))
                         new-cases
                         infos))
                 (new-bindings
                    (map (lambda (var name fvs cases lann lrann)
                           `(,var ,(build-lambda cases name fvs lann) ,lrann))
                         vars
                         names
                         free-vars
                         new-cases
                         lanns
                         lranns)))
            (for table infos (custom_hash_table_merge! fv-info table))
            (for key vars (custom_hash_table_delete! fv-info key))
            (build-letrec* new-bindings new-body (ir-letrec*-ann ir))))
        (else (walk-ir ir pass))))
    (pass ir)))

(define (convert-closures ir)
  (define (free-lambda-freevars init) (ir-lambda-freevars init))
  (define (free-lambda-cases init) (ir-lambda-cases init))
  (define (free-lambda-ann init) (ir-lambda-ann init))
  (define (closure-ref-expr clo num)
    (build-primcall 'closure-ref
                    `(,(build-lexical-reference clo #t #f) ,(build-quote num #f))
                    #f))
  (define (closure-set-expr clo num value)
    (build-primcall 'closure-set!
                    `(,(build-lexical-reference clo #t #f) ,(build-quote num #f) ,value)
                    #f))
  (let convert-closures ((ir ir) (replace '()))
    (define (convert ir)
      (cond
        ((ir-reference? ir)
          (let ((var (ir-reference-var ir)))
            (cond ((assq var replace) => cdr) (else ir))))
        ((ir-letrec*? ir)
          (let* ((bindings (ir-letrec*-bindings ir))
                 (vars (map car bindings))
                 (inits (map cadr bindings))
                 (lranns (map caddr bindings))
                 (body (convert (ir-letrec*-body ir)))
                 (ann (ir-letrec*-ann ir))
                 (names (map ir-lambda-name inits))
                 (free-lists (map free-lambda-freevars inits))
                 (cases-list (map free-lambda-cases inits))
                 (lanns (map free-lambda-ann inits))
                 (var-labels
                    (map (lambda (v)
                           (string->symbol (string-append (symbol->string (variable-name v))
                                                          "-label")))
                         vars))
                 (closure-vars (map (lambda (_) (build-variable 'closure #f)) vars))
                 (new-cases
                    (map (lambda (clo free-vars cases)
                           (map (lambda (clause)
                                  (let ((case-args (car clause)) (case-body (cadr clause)))
                                    (list (cons clo case-args)
                                          (convert-closures case-body
                                                            (map (lambda (fv num)
                                                                   `(,fv .
                                                                         ,(closure-ref-expr clo num)))
                                                                 free-vars
                                                                 (iota (length free-vars) 1))))))
                                cases))
                         closure-vars
                         free-lists
                         cases-list))
                 (fvars-cnt (map length free-lists))
                 (new-label-bindings
                    (map (lambda (label name cases lann lrann)
                           `(,label ,(build-lambda cases name '() lann) ,lrann))
                         var-labels
                         names
                         new-cases
                         lanns
                         lranns))
                 (new-closure-bindings
                    (map (lambda (var fvar-cnt label)
                           `(,var ,(build-primcall 'closure
                                                   (list (build-quote fvar-cnt #f)
                                                         (build-quote label #f))
                                                   #f)))
                         vars
                         fvars-cnt
                         var-labels))
                 (init-sets
                    (apply append
                           (map (lambda (clo free-vars)
                                  (map (lambda (fv num)
                                         (closure-set-expr clo
                                                           num
                                                           (convert (build-lexical-reference fv
                                                                                             #t
                                                                                             #f))))
                                       free-vars
                                       (iota (length free-vars) 1)))
                                vars
                                free-lists))))
            (build-letrec* new-label-bindings
                           (build-let new-closure-bindings (build-begin `(,@init-sets ,body) #f) #f)
                           ann)))
        (else (walk-ir ir convert))))
    (convert ir)))

;; The bytecode does not support raw comparison operators, only
;; branching versions.  Replace comparison ops with branching +
;; comparison if in an 'if' test position, otherwise replace with a
;; branch + true/false constant result.
(define jcmp
  '((LT . JLT) (GT . JGT) (LTE . JLTE) (GTE . JGTE) (EQ . JEQ) (EQV . JEQV)))
(define (lower-comparisons ir)
  (cond
    ;; If it's already behind a if test, it's okay
    ((and (ir-conditional? ir)
          (ir-primcall? (ir-conditional-test ir))
          (assq (ir-primcall-name (ir-conditional-test ir)) jcmp))
      (let* ((test-ir (ir-conditional-test ir))
             (test (ir-primcall-name test-ir))
             (args (ir-primcall-args test-ir))
             (ann (ir-primcall-ann test-ir)))
        (set-ir-primcall-args! test-ir (map lower-comparisons args))
        (set-ir-conditional-then! ir (lower-comparisons (ir-conditional-then ir)))
        (set-ir-conditional-else! ir (lower-comparisons (ir-conditional-else ir)))
        ir))
    ;; Otherwise wrap it in if branch.
    ((and (ir-primcall? ir) (assq (ir-primcall-name ir) jcmp))
      (let ((test (ir-primcall-name ir))
            (args (ir-primcall-args ir))
            (ann (ir-primcall-ann ir)))
        (build-conditional (build-primcall test (map lower-comparisons args) ann)
                           (build-quote #t ann)
                           (build-quote #f ann)
                           ann)))
    (else (walk-ir ir lower-comparisons))))

;; Functions.
(define-record-type fun (make-fun-record code name consts const-list) fun?
  (code fun-code set-fun-code!)
  (name fun-name)
  (consts fun-consts)
  (const-list fun-consts-list set-fun-consts-list!))

(define (make-fun name)
  (make-fun-record '() name (make-hash-table equal?) '()))

(define (add-op fun op) (set-fun-code! fun (cons op (fun-code fun))))

(define func-flag-rest 1)

;; Function list as a parameter (mutable)
(define funs (make-parameter #f))
(define values-entry-fun (make-parameter #f))
(define (add-fun fun)
  (let ((funs (funs))) (set-car! funs (cons fun (car funs)))))
(define (make-funs-list) (cons '() #f))
(define (get-funs) (car (funs)))

(define values-entry-max-argc 255)

;; `(apply values ...)` needs a first-class closure that re-returns its args.
(define (make-values-entry-fun)
  (let ((fun (make-fun "values")))
    (let loop ((argc 1))
      (add-op fun `(IFUNC ,argc 0))
      (if (= argc values-entry-max-argc)
          (begin (add-op fun `(ARGCNT_ERROR ,argc)) (add-op fun `(RETN 1 ,(- argc 1))))
          (let* ((offset (length (fun-code fun))) (jop (list 'JMP 0 0)))
            (add-op fun jop)
            (add-op fun `(RETN 1 ,(- argc 1)))
            (set-car! (cddr jop) (- (length (fun-code fun)) offset))
            (loop (+ argc 1)))))
    fun))

(define (ensure-values-entry-fun)
  (or (values-entry-fun)
     (let ((fun (make-values-entry-fun))) (add-fun fun) (values-entry-fun fun) fun)))

(define (fits-in-int16 value)
  (and (integer? value) (exact? value) (<= -32768 (* 8 value) 32767)))

(define fixnum-max (- (expt 2 60) 1))
(define fixnum-min (- (expt 2 60)))

(define (fits-in-int64 value)
  (and (integer? value) (exact? value) (<= fixnum-min value fixnum-max)))

(define (clamp-fixnum value)
  (display "warning: truncating bignum literal " (current-error-port))
  (write value (current-error-port))
  (newline (current-error-port))
  (cond
    ((< value fixnum-min) fixnum-min)
    ((> value fixnum-max) fixnum-max)
    (else (error "Invalid bignum"))))

(define SYNTAX_OK #f)
(define (normalize-const datum)
  (cond
    ((annotation? datum) (normalize-const (annotation-sexp datum)))
    ;; Syntax constants need to keep their wrap information intact in the
    ;; eval/VM path; stripping to datum loses hygiene and breaks macro output.
    ;((syntax? datum) (if SYNTAX_OK datum (syntax->datum datum)))
    ((pair? datum)
      (cons (normalize-const (car datum)) (normalize-const (cdr datum))))
    ((vector? datum) (list->vector (map normalize-const (vector->list datum))))
    (else datum)))

(define (add-const fun datum)
  (define normalized (normalize-const datum))
  (define consts (fun-consts fun))
  (unless (hash-table-exists? consts normalized)
    (hash-table-set! consts normalized (hash-table-size consts))
    (set-fun-consts-list! fun (cons normalized (fun-consts-list fun))))
  (hash-table-ref consts normalized))

(define (arg-flags args) (if (list? args) 0 func-flag-rest))

(define-record-type const-closure (make-const-closure fun) const-closure?
  (fun const-closure-fun))

(define (loop-info? value) (and (pair? value) (integer? (car value))))

(define (compile-call-args fun env start callee args)
  (let loop ((atop start) (rest (cons callee args)))
    (unless (null? rest)
      (let* ((arg (car rest)) (res (compile arg fun env atop #f)))
        (when (and (integer? res) (not (= res atop))) (add-op fun `(MOV ,atop ,res)))
        (loop (+ atop 1) (cdr rest))))))

(define (compile ir fun env top tail)
  (define (compile-cont ir) (compile ir fun env top #f))
  (define (finish res) (if tail (begin (add-op fun `(RET ,res))) res))
  (define (resolve-const-closure datum)
    (if (and (const-closure? datum) (variable? (const-closure-fun datum)))
        (let ((in-env (assq (const-closure-fun datum) env)))
          (if in-env (make-const-closure (cdr in-env)) datum))
        datum))
  (cond
    ((ir-letrec*? ir)
      (let* ((bindings (ir-letrec*-bindings ir))
             (vars (map car bindings))
             (inits (map cadr bindings))
             (label-funs (map (lambda (init) (make-fun (ir-lambda-name init))) inits))
             (label-env (map cons vars label-funs))
             (label-name-env (map cons (map variable-name vars) label-funs)))
        (for-each (lambda (func init _var)
                    (add-fun func)
                    (let loop ((rest (ir-lambda-cases init)))
                      (unless (null? rest)
                        (let* ((case (car rest))
                               (args (car case))
                               (lbody (cadr case))
                               (arg-list (to-proper args))
                               (arg-env (map cons arg-list (iota (length arg-list) 0)))
                               (new-env (append arg-env label-name-env label-env env))
                               (last? (null? (cdr rest)))
                               (arg-cnt (length arg-list))
                               (flags (arg-flags args)))
                          (add-op func `(FUNC ,arg-cnt ,flags))
                          (if last? (add-op func `(ARGCNT_ERROR ,arg-cnt)))
                          (if last?
                              (compile lbody func new-env arg-cnt #t)
                              (let* ((offset (length (fun-code func))) (jop (list 'JMP 0 0)))
                                (add-op func jop)
                                (compile lbody func new-env arg-cnt #t)
                                (set-car! (cddr jop) (- (length (fun-code func)) offset))))
                          (loop (cdr rest))))))
                  label-funs
                  inits
                  vars)
        (compile (ir-letrec*-body ir)
                 fun
                 (append label-name-env label-env env)
                 top
                 tail)))
    ((ir-let? ir)
      (let* ((bindings (ir-let-bindings ir))
             (vars (map car bindings))
             (inits (map cadr bindings))
             (regs (iota (length vars) top)))
        (for (init reg) (inits regs)
          (let ((res (compile init fun env reg #f)))
            (when (and (integer? res) (not (= res reg))) (add-op fun `(MOV ,reg ,res)))))
        (compile (ir-let-body ir)
                 fun
                 (append (map cons vars regs) env)
                 (+ top (length vars))
                 tail)))
    ((ir-reference? ir)
      (let* ((var (ir-reference-var ir))
             (in-env (or (assq var env) (assq (variable-name var) env))))
        (cond
          (in-env
            (let ((res (cdr in-env)))
              (if (integer? res)
                  (finish res)
                  (begin (add-op fun `(CONST ,top ,(add-const fun res))) (finish top)))))
          (else
            (add-op fun
                    `(LOOKUP ,top ,(add-const fun (variable-full-name (ir-reference-var ir)))))
            (finish top)))))
    ((ir-quote? ir)
      (let ((datum (resolve-const-closure (ir-quote-datum ir))))
        (if (fits-in-int16 datum)
            (add-op fun `(KSHORT ,top ,(* 8 datum)))
            (add-op fun `(CONST ,top ,(add-const fun datum))))
        (finish top)))
    ((ir-conditional? ir)
      (let ((test (ir-conditional-test ir))
            (then (ir-conditional-then ir))
            (else (ir-conditional-else ir)))
        (if (and (ir-primcall? test) (assq (ir-primcall-name test) jcmp))
            (compile (build-primcall (cdr (assq (ir-primcall-name test) jcmp))
                                     (ir-primcall-args test)
                                     (ir-primcall-ann test))
                     fun
                     env
                     top
                     #f)
            (let ((treg (compile test fun env top #f)))
              ;; IF uses reg as stack top metadata and reads test from data.
              (add-op fun `(IF ,top ,treg))))
        (let* ((offset (length (fun-code fun))) (brop (list 'JMP top 0)))
          (add-op fun brop)
          (let ((then-res (compile then fun env top tail)))
            (when (and (not tail) (integer? then-res) (not (= then-res top)))
              (add-op fun `(MOV ,top ,then-res))))
          ;; If not in tail position, an extra JMP is inserted before the else
          ;; path. Account for that so the false branch lands on else code.
          (set-car! (cddr brop) (+ (- (length (fun-code fun)) offset) (if tail 0 1))))
        (let ((offset (length (fun-code fun))) (jop (list 'JMP top 0)))
          (unless tail (add-op fun jop))
          (let ((res (compile else fun env top tail)))
            (when (and (not tail) (integer? res) (not (= res top)))
              (add-op fun `(MOV ,top ,res)))
            (set-car! (cddr jop) (- (length (fun-code fun)) offset))
            (if tail res top)))))
    ((ir-application? ir)
      (let ((func (ir-application-fun ir)) (args (ir-application-args ir)))
        (cond
          ((and (ir-reference? func)
                (assq (ir-reference-var func) env)
                (loop-info? (cdr (assq (ir-reference-var func) env))))
            (let* ((loop-info (cdr (assq (ir-reference-var func) env)))
                   (base (car loop-info))
                   (offset (- top base)))
              (let loop ((rest (reverse args)) (reg (+ top (length args) -1)))
                (unless (null? rest)
                  (let ((res (compile (car rest) fun env reg #f)))
                    (when (and (integer? res) (not (= res reg))) (add-op fun `(MOV ,reg ,res)))
                    (add-op fun `(MOV ,(- reg offset) ,reg))
                    (loop (cdr rest) (- reg 1)))))
              (let ((jop (list 'JMP 0 (length (fun-code fun)))))
                (add-op fun jop)
                (set-cdr! loop-info (cons jop (cdr loop-info))))
              #f))
          ((ir-application-well-known ir)
            (begin
              (compile func fun env top #f)
              (for-each (lambda (arg reg)
                          (let ((res (compile arg fun env reg #f)))
                            (when (and (integer? res) (not (= res reg)))
                              (add-op fun `(MOV ,reg ,res)))))
                        args
                        (iota (length args) (+ top 1)))
              (add-op fun `(,(if tail 'LCALLT 'LCALL) ,top ,(+ 1 (length args))))))
          (else
            (begin
              (compile-call-args fun env (+ top 1) func args)
              (add-op fun `(CLOSURE_GET ,top ,(+ top 1) 0))
              (add-op fun `(,(if tail 'LCALLT 'LCALL) ,top ,(+ 2 (length args)))))))
        (if tail #f top)))
    ((ir-loop? ir)
      (let* ((bindings (ir-loop-args ir))
             (vars (map car bindings))
             (inits (map cadr bindings))
             (next-top (+ top (length vars)))
             (loop-info (cons top '()))
             (loop-env
                (append (map cons vars (iota (length vars) top))
                        (list (cons (ir-loop-name ir) loop-info))
                        env)))
        (for-each (lambda (init reg)
                    (let ((res (compile init fun env reg #f)))
                      (when (and (integer? res) (not (= res reg))) (add-op fun `(MOV ,reg ,res)))))
                  (reverse inits)
                  (reverse (iota (length vars) top)))
        (let ((loop-pc (length (fun-code fun))))
          (add-op fun `(LOOP ,top ,(length vars)))
          (let ((body-res (compile (ir-loop-body ir) fun loop-env next-top tail)))
            (for-each (lambda (jop)
                        (set-car! (cddr jop) (- loop-pc (caddr jop))))
                      (cdr loop-info))
            body-res))))
    ((ir-primcall? ir)
      (let ((op (ir-primcall-name ir)) (args (ir-primcall-args ir)))
        (cond
          ((eq? op 'closure)
            (let* ((cnt (ir-quote-datum (car args))) (label (ir-quote-datum (cadr args))))
              (cond
                ((assq label env) =>
                   (lambda (entry)
                     (add-op fun `(CONST ,top ,(add-const fun (cdr entry))))
                     (add-op fun `(CLOSURE ,top ,cnt))
                     (finish top)))
                (else (error "Unknown label in closure:" label)))))
          ((eq? op 'closure-ref)
            (let* ((clo (car args))
                   (slot (cadr args))
                   (slot-num (ir-quote-datum slot))
                   (clo-res (compile clo fun env top #f)))
              (add-op fun `(CLOSURE_GET ,top ,clo-res ,slot-num))
              (finish top)))
          ((eq? op 'closure-set!)
            (let* ((clo (car args))
                   (slot (cadr args))
                   (val (caddr args))
                   (slot-num (ir-quote-datum slot))
                   (val-res (compile val fun env top #f))
                   (clo-res (compile clo fun env (+ top 1) #f)))
              (add-op fun `(CLOSURE_SET ,val-res ,clo-res ,slot-num))
              (finish top)))
          ((eq? op 'VALUES)
            (cond
              ((null? args)
                (if tail
                    (add-op fun `(RETN ,top 0))
                    (begin (add-op fun `(KSHORT ,top ,undefined-tag)) (finish top))))
              (else
                (let loop ((atop top) (rest args))
                  (unless (null? rest)
                    (let ((res (compile (car rest) fun env atop #f)))
                      (when (and (integer? res) (not (= res atop))) (add-op fun `(MOV ,atop ,res)))
                      (loop (+ atop 1) (cdr rest)))))
                (if tail (add-op fun `(RETN ,top ,(length args))) (finish top)))))
          ((eq? op 'CALL_WITH_VALUES)
            (let* ((producer (car args))
                   (consumer (cadr args))
                   (consumer-clo (+ top 1))
                   (producer-fn (+ top 2))
                   (producer-clo (+ top 3))
                   (consumer-res (compile consumer fun env consumer-clo #f))
                   (producer-res (compile producer fun env producer-clo #f)))
              (when (and (integer? consumer-res) (not (= consumer-res consumer-clo)))
                (add-op fun `(MOV ,consumer-clo ,consumer-res)))
              (when (and (integer? producer-res) (not (= producer-res producer-clo)))
                (add-op fun `(MOV ,producer-clo ,producer-res)))
              ;; Arrange the same frame shape as a normal closure call:
              ;; [fn][closure][arg...]. That lets LCALL_N reuse argcnt from
              ;; RETN without moving anything.
              (add-op fun `(CLOSURE_GET ,top ,consumer-clo 0))
              (add-op fun `(CLOSURE_GET ,producer-fn ,producer-clo 0))
              ;; Producer is a thunk, so it uses the VM's zero-arg call
              ;; convention.
              (add-op fun `(LCALL ,producer-fn 2))
              (add-op fun `(,(if tail 'LCALLT_N 'LCALL_N) ,top 0))
              (if tail #f top)))
          ((eq? op 'FOREIGN_CALL)
            ;; args = combined signature object followed by runtime call arguments.
            (let loop ((atop top) (rest args))
              (unless (null? rest)
                (let ((res (compile (car rest) fun env atop #f)))
                  (unless (integer? res) (error "FOREIGN_CALL argument not in register"))
                  (unless (= res atop) (add-op fun `(MOV ,atop ,res)))
                  (loop (+ atop 1) (cdr rest)))))
            (add-op fun `(FOREIGN_CALL ,top ,top ,(length args)))
            (finish top))
          (else
            (let loop ((atop top) (rest args) (argres '()))
              (if (null? rest)
                  (let ((argres (reverse argres)))
                    (add-op fun
                            `(,op ,@(if (memq op '(STORE_CHAR STORE)) '() (list top)) ,@argres)))
                  (let* ((arg (car rest))
                         (res (compile arg fun env atop #f))
                         (next (if (and (integer? res) (= res atop)) (+ atop 1) atop)))
                    (loop next (cdr rest) (cons res argres)))))
            (finish top)))))
    ((ir-define? ir)
      (let ((var (ir-define-var ir)))
        (if (global-values-var? var)
            (let ((values-clo (make-const-closure (ensure-values-entry-fun))))
              (add-op fun `(CONST ,top ,(add-const fun values-clo)))
              (add-op fun `(DEFINE ,top ,(add-const fun (variable-full-name var))))
              (finish top))
            (let ((exp (compile-cont (ir-define-exp ir))))
              (add-op fun `(DEFINE ,exp ,(add-const fun (variable-full-name var))))
              (finish exp)))))
    ((and (ir-assignment? ir) (ir-assignment-global? ir))
      (let* ((var (ir-assignment-var ir)) (exp (compile-cont (ir-assignment-exp ir))))
        (add-op fun `(DEFINE ,exp ,(add-const fun (variable-full-name var))))
        (finish exp)))
    ((ir-begin? ir)
      (let* ((exps (ir-begin-exps ir)) (body (reverse exps)))
        (for-each compile-cont (reverse (cdr body)))
        (compile (car body) fun env top tail)))
    ((ir-void? ir) (add-op fun `(KSHORT ,top ,undefined-tag)) (finish top))
    (else (error "UNKNOWN OP:" ir))))

(define (read-file port)
  (define r (make-reader port "<stdin>"))
  (let loop ((ann (read r)) (res '()))
    (if (eof-object? ann) (reverse res) (loop (read r) (cons ann res)))))

(define (print-bc fun)
  (display "Compiled fun ")
  (display (fun-name fun))
  (display "\nConsts:\n")
  (for-each (lambda (c) (write c) (newline)) (reverse (fun-consts-list fun)))
  (display "\nBC:\n")
  (for-each (lambda (bc) (display bc) (newline)) (reverse (fun-code fun)))
  (newline))

(define (write-uint v n p)
  (let loop ((v v) (n n))
    (when (> n 0)
      (write-u8 (modulo v 256) p)
      (loop (arithmetic-shift v -8) (- n 1)))))

(define (align8 x) (if (= 0 (modulo x 8)) x (+ x (- 8 (modulo x 8)))))

(define (bc-fixnum? c) (and (integer? c) (exact? c) (fits-in-int64 c)))
(define (bc-flonum? c) (and (inexact? c) (real? c)))
(define (heap-obj? c)
  (or (string? c)
     (symbol? c)
     (bc-flonum? c)
     (pair? c)
     (vector? c)
     (fun? c)
     (const-closure? c)))

(define (obj-tag o)
  (cond
    ((bc-flonum? o) flonum-tag)
    ((symbol? o) symbol-tag)
    ((pair? o) cons-tag)
    ((vector? o) vector-tag)
    ((const-closure? o) closure-tag)
    (else ptr-tag)))

(define (encode-immediate o)
  (cond
    ((bc-fixnum? o) (* 8 o))
    ((and (integer? o) (exact? o)) (* 8 (clamp-fixnum o)))
    ((eq? o #t) true-rep)
    ((eq? o #f) false-rep)
    ((null? o) nil-tag)
    ((char? o) (+ (arithmetic-shift (char->integer o) 8) char-tag))
    ((eof-object? o) eof-tag)
    (else #f)))

(define (serialize-object o writer)
  (define (w32 v) (writer 'u32 v))
  (define (w64 v) (writer 'u64 v))
  (define (word v) (writer 'word v))
  (cond
    ((bc-flonum? o) (w32 flonum-tag) (w32 0) (writer 'double o))
    ((string? o)
      (w32 string-tag)
      (w32 0)
      (w64 (* 8 (string-length o)))
      (string-for-each (lambda (c) (writer 'u8 (char->integer c))) o)
      (writer 'u8 0)
      (writer 'align 8))
    ((symbol? o)
      (w32 symbol-tag)
      (w32 0)
      (word (symbol->string o))
      (if (eq? o 'symbol-table)
          (word (writer 'symbol-table-value #f))
          ;(w64 undefined-tag)
          (w64 dead-tag))
      (w64 0)
      (w64 0))
    ((pair? o) (w32 cons-tag) (w32 0) (word (car o)) (word (cdr o)))
    ((vector? o)
      (w32 vector-tag)
      (w32 0)
      (w64 (* 8 (vector-length o)))
      (vector-for-each word o))
    ((const-closure? o)
      (w32 closure-tag)
      (w32 0)
      (w64 8)
      (word (const-closure-fun o)))
    ((fun? o)
      (let* ((code (reverse (fun-code o)))
             (consts (reverse (fun-consts-list o)))
             (const-cnt (length consts)))
        (w32 func-tag)
        (w32 0)
        (word (fun-name o))
        (w64 const-cnt)
        (w64 (length code))
        (for-each word consts)
        (for-each (lambda (ins idx)
                    (let ((op (car ins)))
                      (writer 'u8 (cdr (assq op opcodes)))
                      (writer 'u8 (second ins))
                      (cond
                        ((memq op '(LOOKUP CONST DEFINE))
                          (writer 'u16 (+ idx (* 2 (- const-cnt (third ins))))))
                        ((memq op ops_abc) (writer 'u8 (third ins)) (writer 'u8 (fourth ins)))
                        ((memq op ops_ad) (writer 'u16 (third ins)))
                        (else (writer 'u16 (if (pair? (cddr ins)) (third ins) 0))))))
                  code
                  (iota (length code)))
        (writer 'align 8)))))

(define (collect-objects roots)
  (define canon (make-hash-table equal?))
  (define seen (make_custom_hash_table))
  (define order '())
  (define (mark! c)
    (when (heap-obj? c)
      (unless (hash-table-exists? canon c) (hash-table-set! canon c c))
      (let ((k (hash-table-ref canon c)))
        (unless (custom_hash_table_exists? seen k)
          (custom_hash_table_set! seen k #t)
          (set! order (cons k order))
          (cond
            ((symbol? k) (mark! (symbol->string k)))
            ((pair? k) (mark! (car k)) (mark! (cdr k)))
            ((vector? k) (vector-for-each mark! k))
            ((const-closure? k) (mark! (const-closure-fun k)))
            ((fun? k) (mark! (fun-name k)) (for-each mark! (reverse (fun-consts-list k))))
            (else #f))))))
  (for-each mark! roots)
  (values (reverse order) canon))

(define (emit-image objects canon symbol-table-value)
  (define offs (make_custom_hash_table))
  (define pos 0)
  (define (pass1 type val)
    (case type
      ((u8) (set! pos (+ pos 1)))
      ((u16) (set! pos (+ pos 2)))
      ((u32) (set! pos (+ pos 4)))
      ((u64 double word) (set! pos (+ pos 8)))
      ((symbol-table-value) #f)
      ((align)
        (let ((m (modulo pos val))) (unless (= m 0) (set! pos (+ pos (- val m))))))))

  (for-each (lambda (o) (custom_hash_table_set! offs o pos) (serialize-object o pass1))
            objects)

  (let ((p (open-output-bytevector)))
    (define (w8 v) (write-u8 v p) (set! pos (+ pos 1)))
    (define (pass2 type val)
      (case type
        ((u8) (w8 val))
        ((u16) (write-uint val 2 p) (set! pos (+ pos 2)))
        ((u32) (write-uint val 4 p) (set! pos (+ pos 4)))
        ((u64) (write-uint val 8 p) (set! pos (+ pos 8)))
        ((double) (write-double val p) (set! pos (+ pos 8)))
        ((symbol-table-value) symbol-table-value)
        ((word)
          (let ((imm (encode-immediate val)))
            (if imm
                (write-uint imm 8 p)
                (let ((o (hash-table-ref canon val)))
                  (write-uint (+ (custom_hash_table_ref offs o) (obj-tag o)) 8 p)))
            (set! pos (+ pos 8))))
        ((align) (let loop () (unless (= 0 (modulo pos val)) (w8 0) (loop))))))
    (set! pos 0)
    (for-each (lambda (o) (serialize-object o pass2)) objects)
    (values (get-output-bytevector p) offs)))

(define (build-symbol-table objects)
  (fold-right (lambda (o res) (if (symbol? o) (cons (cons (symbol->string o) o) res) res))
              '()
              objects))

(include "pp.scm")
(define (debug-print ir)
  (pretty-print (ir-pp ir))
  (newline)
  (flush-output-port)
  ir)

(define (read-all-forms port)
  (let loop ((form (read port)) (acc '()))
    (if (eof-object? form) (reverse acc) (loop (read port) (cons form acc)))))

(define (read-forms path)
  (let ((port (open-input-file path)))
    (let ((forms (read-all-forms port))) (close-input-port port) forms)))

(define (read-forms-from-string str)
  (let ((port (open-input-string str)))
    (let ((forms (read-all-forms port))) (close-input-port port) forms)))

(define default-import-forms
  (read-forms-from-string "(import (scheme base)(scheme case-lambda)(scheme char)(scheme complex)(scheme cxr)(scheme eval)(scheme file)(scheme inexact)(scheme lazy)(scheme load)(scheme process-context)(scheme read)(scheme repl)(scheme time)(scheme write)(scheme r5rs))"))

(define (form-sexp form) (if (annotation? form) (annotation-sexp form) form))

(define (import-form? form)
  (let ((sexp (form-sexp form)))
    (and (pair? sexp) (eq? (form-sexp (car sexp)) 'import))))

(define (ensure-leading-import forms)
  (if (and (pair? forms) (import-form? (car forms)))
      forms
      (append default-import-forms forms)))

(define (read-ir-from-file file)
  (expander-setup)
  (let ((runtime-forms (read-forms "runtime.scm"))
        (eval-forms (read-forms "eval.scm"))
        (input-forms (ensure-leading-import (read-forms file))))
    (build-begin (list ;(expand-program runtime-forms "")
                  ;(expand-program eval-forms "")
                  (expand-program input-forms "BOOTSTRAP")))))

(define (compile-ir-to-bitcode ir)
  (parameterize ((funs (make-funs-list)))
    (let* ((lowered
              (-> ir
                  simple-pass
                  fix-letrec
                  assignment-conversion
                  lower-comparisons
                  recover-let
                  ;debug-print
                  name-lambdas
                  fix-all
                  uncover-free
                  escape-analyze
                  debug-print
                  lower-loops
                  debug-print
                  required-free-vars
                  ;debug-print
                  ;convert-closures
             ))
           (main (make-fun "main")))
      ;(exit 0)
      (compile lowered main '() 0 #f)
      (add-op main `(RET 0))
      (add-fun main)
      (get-funs))))

(define (normalize-u8 v) (modulo v 256))
(define (normalize-u16 v) (modulo v 65536))

(define (ins->word ins idx const-cnt)
  (let* ((op (car ins))
         (opc
            (cond
              ((assq op opcodes) => cdr)
              (else (error "Unknown opcode in ins->word:" op))))
         (reg (second ins))
         (data
            (cond
              ((memq op '(LOOKUP CONST DEFINE)) (+ idx (* 2 (- const-cnt (third ins)))))
              ((memq op ops_abc) (+ (third ins) (* 256 (fourth ins))))
              ((memq op ops_ad) (third ins))
              (else (if (pair? (cddr ins)) (third ins) 0)))))
    (+ (normalize-u8 opc)
       (* 256 (normalize-u8 reg))
       (* 65536 (normalize-u16 data)))))

(define (roots->runtime-payload roots)
  (let ((ids (make_custom_hash_table)) (seen (make_custom_hash_table)))
    (letrec ((const->runtime
                (lambda (c)
                  (cond
                    ((fun? c) (vector 'fun-ref (custom_hash_table_ref ids c)))
                    ((const-closure? c)
                      (vector 'closure-ref (custom_hash_table_ref ids (const-closure-fun c))))
                    ((pair? c)
                      (cond
                        ((custom_hash_table_exists? seen c) (custom_hash_table_ref seen c))
                        (else
                          (let ((cell (cons #f #f)))
                            (custom_hash_table_set! seen c cell)
                            (set-car! cell (const->runtime (car c)))
                            (set-cdr! cell (const->runtime (cdr c)))
                            cell))))
                    ((vector? c)
                      (cond
                        ((custom_hash_table_exists? seen c) (custom_hash_table_ref seen c))
                        (else
                          (let* ((len (vector-length c)) (res (make-vector len)))
                            (custom_hash_table_set! seen c res)
                            (do ((i 0 (+ i 1)))
                                 ((= i len) res)
                                 (vector-set! res i (const->runtime (vector-ref c i))))))))
                    (else c))))
             (fun->runtime
                (lambda (fun)
                  (let* ((consts (reverse (fun-consts-list fun)))
                         (code (reverse (fun-code fun)))
                         (const-cnt (length consts)))
                    (vector (custom_hash_table_ref ids fun)
                            (fun-name fun)
                            (map const->runtime consts)
                            (map (lambda (ins idx) (ins->word ins idx const-cnt))
                                 code
                                 (iota (length code))))))))
      (for-each (lambda (fun i) (custom_hash_table_set! ids fun i))
                roots
                (iota (length roots)))
      (vector (custom_hash_table_ref ids (car roots)) (map fun->runtime roots)))))

(define (serialize-bitcode roots)
  (let ((main (car roots)))
    (let*-values (((objects canon) (collect-objects roots))
                  ((symbol-table) (build-symbol-table objects))
                  ((objects canon) (collect-objects (cons symbol-table roots)))
                  ((image offs) (emit-image objects canon symbol-table)))
      (values image
              (+ (custom_hash_table_ref offs (hash-table-ref canon main)) ptr-tag)))))

(define (compile-file dump-bc)
  (lambda (file)
    (let ((out (open-binary-output-file (string-append file ".bc")))
          (roots (compile-ir-to-bitcode (read-ir-from-file file))))
      (let-values (((image entry) (serialize-bitcode roots)))
        (string-for-each (lambda (c) (write-u8 (char->integer c) out)) "HAWK")
        (write-uint 0 8 out)
        (write-uint (bytevector-length image) 8 out)
        (write-uint entry 8 out)
        (write-bytevector image out))
      (close-output-port out)
      (when dump-bc (for-each print-bc roots)))))
