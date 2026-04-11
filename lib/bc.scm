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

(define (cont-pass ir c)
  ;; (display "Cont pass:")
  ;; (display (ir->sexp ir))
  ;; (newline)
  (match ir
    (#(app ,fun ,sexps ,ann)
      (vector-set! ir 1 (c fun))
      (vector-set! ir 2 (map c sexps)))
    (#(if ,test ,then ,else ,ann)
      (vector-set! ir 1 (c test))
      (vector-set! ir 2 (c then))
      (vector-set! ir 3 (c else)))
    (#(ref ,var ,global ,mutable ,ann) #t)
    (#(set! ,var ,exp ,global? ,ann) (vector-set! ir 2 (c exp)))
    (#(lambda ,cases ,ann)
      (vector-set! ir
                   1
                   (map (lambda (clause) (list (car clause) (c (cadr clause)))) cases)))
    (#(nlambda ,name ,cases ,ann)
      (vector-set! ir
                   2
                   (map (lambda (clause) (list (car clause) (c (cadr clause)))) cases)))
    (#(nlambda ,name (free ,free ___) ,cases ,ann)
      (vector-set! ir
                   3
                   (map (lambda (clause) (list (car clause) (c (cadr clause)))) cases)))
    (#(letrec* ,bindings ,body ,ann)
      (for val bindings (set-car! (cdr val) (c (second val))))
      (vector-set! ir 2 (c body))
      ir)
    (#(let ,bindings ,body ,ann)
      (for val bindings (set-car! (cdr val) (c (second val))))
      (vector-set! ir 2 (c body))
      ir)
    (#(quote ,datum ,ann) #t)
    (#(begin ,sexps ,ann) (vector-set! ir 1 (map c sexps)))
    (#(void ,ann) #t)
    (#(define ,var ,exp ,ann) (vector-set! ir 2 (c exp)))

    ;; From this file:
    (#(primcall ,op ,args ,ann) (vector-set! ir 2 (map c args)))
    (,else (error "Invalid IR:" ir)))
  ir)

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
                  (and arity (= nargs arity))))
            (build-primcall (cdr (assq name primcalls)) (map simple-pass args) ann))
          (else (cont-pass ir simple-pass)))))
    (else (cont-pass ir simple-pass))))

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

      (else (cont-pass expr (lambda (child) (convert child boxes))))))

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
     (cont-pass ir recover-let)))

;; adds name field to lambdas.
(define (name-lambdas ir)
  (define (name-lambdas-int ir cur)
    (define (name-cases cases name)
      (map (lambda (clause) `(,(car clause) ,(name-lambdas-int (cadr clause) name)))
           cases))
    (define (named-lambda cases name ann)
      (build-nlambda name (name-cases cases name) ann))
    (define (rewrite-define ir)
      (and-let ((var (and (ir-define? ir) (ir-define-var ir)))
                (exp (ir-define-exp ir))
                (cases (and (ir-lambda? exp) (ir-lambda-cases exp))))
               (let ((lam-ann (ir-lambda-ann exp))
                     (define-ann (ir-define-ann ir))
                     (name (symbol->string (variable-name var))))
                 (build-define var (named-lambda cases name lam-ann) define-ann))))
    (define (rewrite-lambda ir)
      (and-let ((cases (and (ir-lambda? ir) (ir-lambda-cases ir))))
               (let ((lam-ann (ir-lambda-ann ir)))
                 (named-lambda cases (string-append cur "-anon") lam-ann))))
    (define (name-pass ir)
      (or (rewrite-define ir) (rewrite-lambda ir) (cont-pass ir name-pass)))
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
            ;; TODO add a setter once we've normalized nlambda
            (vector-set! init 2 (rewrite-cases (ir-nlambda-cases init)))))
        (vector-set! ir 2 (fix-all (ir-letrec*-body ir)))
        ir))
    ((ir-nlambda? ir)
      (let* ((name (ir-nlambda-name ir))
             (ann (ir-nlambda-ann ir))
             (tmp (build-variable (string->symbol name) #f)))
        (vector-set! ir 2 (rewrite-cases (ir-nlambda-cases ir)))
        (build-letrec* `((,tmp ,ir #f)) (build-lexical-reference tmp #f #f) #f)))
    (else (cont-pass ir fix-all))))

(define (uncover-free ir)
  (let uncover-free ((ir ir) (bindings '()) (fv-info (make-hash-table eq?)))
    (define (pass ir)
      (match ir
        (#(ref ,var ,unused ,unused2 ,unused3)
          (when (memq var bindings) (hash-table-set! fv-info var #t))
          ir)
        (#(let ((,vars ,(pass inits)) ___) ,body ,ann)
          (let ((new-body (uncover-free body (append vars bindings) fv-info)))
            (for key vars (hash-table-delete! fv-info key))
            `#(let ,(omap (vars inits) (vars inits) `(,vars ,inits)) ,new-body ,ann)))
        ;; TODO the same as let?
        ;; ((loop ,vars ,name ,body ,(pass args) ___)
        ;;   (let ((new-body (uncover-free body (append vars bindings) fv-info)))
        ;;     (for key vars (hash-table-delete! fv-info key))
        ;;     `(loop ,vars ,name ,new-body ,args ___)))
        (#(letrec* ((,vars #(nlambda ,name ,cases ,lann) ,lrann) ___) ,body ,ann)
          (let* ((new-env (append vars bindings))
                 (infos (omap _ vars (make-hash-table eq?)))
                 (new-cases
                    (omap (cases info)
                          (cases infos)
                          (map (lambda (clause)
                                 (let ((args (car clause)) (lbody (cadr clause)))
                                   (list args
                                         (uncover-free lbody (append (to-proper args) new-env) info))))
                               cases)))
                 (new-body (uncover-free body new-env fv-info))
                 (free-vars
                    (omap (cases table)
                          (cases infos) ;; for each lambda
                          (for clause cases
                            (for key (to-proper (car clause)) (hash-table-delete! table key)))
                          (hash-table-keys table))))

            (for table infos (hash-table-merge! fv-info table))
            (for key vars (hash-table-delete! fv-info key))
            (let ((bindings
                     (omap (var name free-vars cases lann lrann)
                           (vars name free-vars new-cases lann lrann)
                           `(,var #(nlambda ,name (free ,@free-vars) ,cases ,lann) ,lrann))))
              `#(letrec* ,bindings ,new-body ,ann))))
        (,else (cont-pass ir pass))))
    (pass ir)))

(define (convert-closures ir)
  (define clo-counter 0)
  (define (fresh-clo)
    (set! clo-counter (+ clo-counter 1))
    (vector 'var
            (string->symbol (string-append "clo." (number->string clo-counter)))
            #f
            #f))
  (let convert-closures ((ir ir) (replace '()))
    (define (convert ir)
      (match ir
        (#(ref ,var ,unused ,unused2 ,unused3)
          (cond ((assq var replace) => (lambda (newvar) (cdr newvar))) (else ir)))
        (#(letrec* ((,vars #(nlambda ,name (free ,free ___) ,cases ,lann) ,lrann) ___)
            ,(convert body)
            ,ann)
          (let* ((var-labels
                    (map (lambda (n)
                           (string->symbol (string-append (symbol->string (vector-ref n 1))
                                                          "-label")))
                         vars))
                 (closure-vars (map (lambda (_) (fresh-clo)) vars))
                 (new-cases
                    (omap (clo free cases)
                          (closure-vars free cases) ;; for each lambda
                          (map (lambda (clause)
                                 (let ((case-args (car clause)) (body (cadr clause)))
                                   (list (cons clo case-args)
                                         (convert-closures body
                                                           (omap (fv num)
                                                                 (free (iota (length free) 1))
                                                                 `(,fv .
                                                                       #(primcall closure-ref
                                                                                  (#(ref ,clo
                                                                                         #f
                                                                                         #t
                                                                                         #f)
                                                                                   #(quote ,num #f))
                                                                                  #f)))))))
                               cases)))
                 (fvars-cnt (map length free))
                 (new-label-bindings
                    (omap (label name cases lann lrann)
                          (var-labels name new-cases lann lrann)
                          `(,label #(nlambda ,name ,cases ,lann) ,lrann)))
                 (new-closure-bindings
                    (omap (var fvar-cnt label)
                          (vars fvars-cnt var-labels)
                          `(,var #(closure ,fvar-cnt #(label ,label))))))
            `#(letrec* ,new-label-bindings
                #(let
                  ,new-closure-bindings
                  #(begin
                     (,@(apply append
                               (omap (clo fvars)
                                     (vars free)
                                     (omap (fv num)
                                           (fvars (iota (length fvars) 1))
                                           `#(primcall closure-set!
                                                       (#(ref ,clo #f #t #f)
                                                        #(quote ,num #f)
                                                        ,(convert `#(ref ,fv #f #t #f)))
                                                       #f))))
                      ,body)
                     #f)
                  #f)
                #f)))
        (,else (cont-pass ir convert))))
    (convert ir)))

;; The bytecode does not support raw comparison operators, only
;; branching versions.  Replace comparison ops with branching +
;; comparison if in an 'if' test position, otherwise replace with a
;; branch + true/false constant result.
(define jcmp
  '((LT . JLT) (GT . JGT) (LTE . JLTE) (GTE . JGTE) (EQ . JEQ) (EQV . JEQV)))
(define (lower-comparisons ir)
  (match ir
    ;; If it's already behind a if test, it's okay
    (#(if #(primcall ,test ,args ,ann1) ,then ,else ,ann2)
      (guard (assq test jcmp))
      `#(if #(primcall ,test ,(map lower-comparisons args) ,ann1)
            ,(lower-comparisons then)
            ,(lower-comparisons else)
            ,ann1))
    ;; Otherwise wrap it in if branch.
    (#(primcall ,test ,args ,ann1)
      (guard (assq test jcmp))
      `#(if #(primcall ,test ,(map lower-comparisons args) ,ann1)
            #(quote #t ,ann1)
            #(quote #f ,ann1)
            ,ann1))
    (,else (cont-pass ir lower-comparisons))))

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
(define (add-fun fun)
  (let ((funs (funs))) (set-car! funs (cons fun (car funs)))))
(define (make-funs-list) (cons '() #f))
(define (get-funs) (car (funs)))

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

(define (compile ir fun env top tail)
  (define (compile-cont ir) (compile ir fun env top #f))
  (define (finish res) (if tail (begin (add-op fun `(RET ,res))) res))
  (match ir
    (#(letrec* ((,vars ,inits ,ann1) ___) ,body ,ann2)
      (let* ((label-funs
                (omap init
                      inits
                      (match init
                        (#(nlambda ,name ,cases ,lann) (make-fun name))
                        (,else (error "Invalid letrec* init in compile:" init)))))
             (label-env (map cons vars label-funs)))
        (for-each (lambda (func init var)
                    (match init
                      (#(nlambda ,name ,cases ,lann)
                        (add-fun func)
                        (let loop ((rest cases))
                          (unless (null? rest)
                            (let* ((case (car rest))
                                   (args (car case))
                                   (lbody (cadr case))
                                   (arg-list (to-proper args))
                                   (arg-env (map cons arg-list (iota (length arg-list) 0)))
                                   (new-env (append arg-env label-env env))
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
                      (,else (error "Invalid letrec* init in compile:" init))))
                  label-funs
                  inits
                  vars)
        (compile body fun (append label-env env) top tail)))
    (#(closure ,cnt #(label ,label))
      (cond
        ((assq label env) =>
           (lambda (entry)
             (add-op fun `(CONST ,top ,(add-const fun (cdr entry))))
             (add-op fun `(CLOSURE ,top ,cnt))
             (finish top)))
        (else (error "Unknown label in closure:" label))))
    (#(let ((,vars ,inits) ___) ,body ,ann)
      (let ((regs (iota (length vars) top)))
        (for (init reg) (inits regs)
          (let ((res (compile init fun env reg #f)))
            (when (and (integer? res) (not (= res reg))) (add-op fun `(MOV ,reg ,res)))))
        (compile body
                 fun
                 (append (map cons vars regs) env)
                 (+ top (length vars))
                 tail)))
    (#(ref ,var ,global ,mutable ,ann)
      (let ((in-env (assq var env)))
        (finish (if in-env
                    (cdr in-env)
                    (begin
                      (add-op fun `(LOOKUP ,top ,(add-const fun (variable-full-name var))))
                      top))))
      ;; TODO possibly needs mov?
    )
    (#(quote ,datum ,ann)
      (if (fits-in-int16 datum)
          (add-op fun `(KSHORT ,top ,(* 8 datum)))
          (add-op fun `(CONST ,top ,(add-const fun datum))))
      (finish top))
    (#(if ,test ,then ,else ,ann)
      (match test
        (#(primcall ,op ,args ,ann)
          (guard (assq op jcmp))
          (compile `#(primcall ,(cdr (assq op jcmp)) ,args ,ann) fun env top #f))
        (,else
          (let ((treg (compile test fun env top #f)))
            ;; IF uses reg as stack top metadata and reads test from data.
            (add-op fun `(IF ,top ,treg)))))
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
          (if tail res top))))
    (#(app ,func ,args ,ann)
      ;; Leave room for func + pointer.
      (let loop ((top (+ top 1)) (args (cons func args)))
        (unless (null? args)
          (let* ((arg (car args)) (res (compile arg fun env top #f)))
            (when (and (integer? res) (not (= res top))) (add-op fun `(MOV ,top ,res)))
            (loop (+ top 1) (cdr args)))))
      (add-op fun `(CLOSURE_GET ,top ,(+ top 1) 0))
      (add-op fun `(,(if tail 'LCALLT 'LCALL) ,top ,(+ 2 (length args))))
      (if tail #f top))
    (#(primcall closure-ref (,clo ,slot) ,ann)
      (let ((slot-num
               (match slot
                 (#(quote ,num ,ann2) num)
                 (,else (error "Invalid closure-ref slot:" slot)))))
        (let ((clo-res (compile clo fun env top #f)))
          (add-op fun `(CLOSURE_GET ,top ,clo-res ,slot-num))
          (finish top))))
    (#(primcall closure-set! (,clo ,slot ,val) ,ann)
      (let ((slot-num
               (match slot
                 (#(quote ,num ,ann2) num)
                 (,else (error "Invalid closure-set! slot:" slot)))))
        (let* ((val-res (compile val fun env top #f))
               (clo-res (compile clo fun env (+ top 1) #f)))
          (add-op fun `(CLOSURE_SET ,val-res ,clo-res ,slot-num))
          (finish top))))
    (#(primcall FOREIGN_CALL ,args ,ann)
      ;; args = combined signature object followed by runtime call arguments.
      (let loop ((atop top) (args args))
        (unless (null? args)
          (let ((res (compile (car args) fun env atop #f)))
            (unless (integer? res) (error "FOREIGN_CALL argument not in register"))
            (unless (= res atop) (add-op fun `(MOV ,atop ,res)))
            (loop (+ atop 1) (cdr args)))))
      (add-op fun `(FOREIGN_CALL ,top ,top ,(length args)))
      (finish top))
    (#(primcall ,op ,args ,ann)
      (let loop ((atop top) (args args) (argres '()))
        (if (null? args)
            (let ((argres (reverse argres)))
              (add-op fun
                      `(,op ,@(if (memq op '(STORE_CHAR STORE)) '() (list top)) ,@argres)))
            (let* ((arg (car args))
                   (res (compile arg fun env atop #f))
                   (next (if (and (integer? res) (= res atop)) (+ atop 1) atop)))
              (loop next (cdr args) (cons res argres)))))
      (finish top))
    (#(define ,var ,(compile-cont exp) ,ann)
      (add-op fun `(DEFINE ,exp ,(add-const fun (variable-full-name var))))
      (finish exp))
    (#(set! ,var ,(compile-cont exp) #t ,ann)
      (add-op fun `(DEFINE ,exp ,(add-const fun (variable-full-name var))))
      (finish exp))
    (#(begin (,sexps ___ ,tail-sexp) ,ann)
      (map compile-cont sexps)
      (compile tail-sexp fun env top tail))
    (#(void ,ann) (add-op fun `(KSHORT ,top ,undefined-tag)) (finish top))
    (,else (error "UNKNOWN OP:" ir))))

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
  (define seen (make-hash-table eq?))
  (define order '())
  (define (mark! c)
    (when (heap-obj? c)
      (unless (hash-table-exists? canon c) (hash-table-set! canon c c))
      (let ((k (hash-table-ref canon c)))
        (unless (hash-table-exists? seen k)
          (hash-table-set! seen k #t)
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
  (define offs (make-hash-table eq?))
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

  (for-each (lambda (o) (hash-table-set! offs o pos) (serialize-object o pass1))
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
                  (write-uint (+ (hash-table-ref offs o) (obj-tag o)) 8 p)))
            (set! pos (+ pos 8))))
        ((align) (let loop () (unless (= 0 (modulo pos val)) (w8 0) (loop))))))
    (set! pos 0)
    (for-each (lambda (o) (serialize-object o pass2)) objects)
    (values (get-output-bytevector p) offs)))

(define (build-symbol-table objects)
  (fold-right (lambda (o res) (if (symbol? o) (cons (cons (symbol->string o) o) res) res))
              '()
              objects))

(define (debug-print ir) (display (ir->sexp ir)) (newline) ir)

(define empty-library-name (string->symbol ""))

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
    (build-begin (list (expand-program runtime-forms "")
                       (expand-program eval-forms "")
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
                  name-lambdas
                  fix-all
                  uncover-free
                  convert-closures))
           (main (make-fun "main")))
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
  (let ((ids (make-hash-table eq?)) (seen (make-hash-table eq?)))
    (letrec ((const->runtime
                (lambda (c)
                  (cond
                    ((fun? c) (vector 'fun-ref (hash-table-ref ids c)))
                    ((const-closure? c)
                      (vector 'closure-ref (hash-table-ref ids (const-closure-fun c))))
                    ((pair? c)
                      (cond
                        ((hash-table-exists? seen c) (hash-table-ref seen c))
                        (else
                          (let ((cell (cons #f #f)))
                            (hash-table-set! seen c cell)
                            (set-car! cell (const->runtime (car c)))
                            (set-cdr! cell (const->runtime (cdr c)))
                            cell))))
                    ((vector? c)
                      (cond
                        ((hash-table-exists? seen c) (hash-table-ref seen c))
                        (else
                          (let* ((len (vector-length c)) (res (make-vector len)))
                            (hash-table-set! seen c res)
                            (do ((i 0 (+ i 1)))
                                 ((= i len) res)
                                 (vector-set! res i (const->runtime (vector-ref c i))))))))
                    ;; The eval path can reuse existing runtime record objects
                    ;; directly as constants.
                    ((sys:GUARD c 49) c)
                    (else c))))
             (fun->runtime
                (lambda (fun)
                  (let* ((consts (reverse (fun-consts-list fun)))
                         (code (reverse (fun-code fun)))
                         (const-cnt (length consts)))
                    (vector (hash-table-ref ids fun)
                            (fun-name fun)
                            (map const->runtime consts)
                            (map (lambda (ins idx) (ins->word ins idx const-cnt))
                                 code
                                 (iota (length code))))))))
      (for-each (lambda (fun i) (hash-table-set! ids fun i))
                roots
                (iota (length roots)))
      (vector (hash-table-ref ids (car roots)) (map fun->runtime roots)))))

(define (serialize-bitcode roots)
  (let ((main (car roots)))
    (let*-values (((objects canon) (collect-objects roots))
                  ((symbol-table) (build-symbol-table objects))
                  ((objects canon) (collect-objects (cons symbol-table roots)))
                  ((image offs) (emit-image objects canon symbol-table)))
      (values image (+ (hash-table-ref offs (hash-table-ref canon main)) ptr-tag)))))

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
