;; Bytecode generator for hawk

(import (scheme base)
        (scheme write)
        (read)
        (syntax)
        (expand)
        (scheme process-context)
        (scheme file)
        (match)
        (srfi 69)
        (srfi 1)
        (srfi 151)
        ;; gauche
        (rename (only (binary io) write-f64) (write-f64 write-double)))
(include "opcodes.scm")
(include "memory_layout.scm")
(include "fix-letrec.scm")

(define-syntax ->
   (syntax-rules ()
     ((_ arg (command args ...) rest ...) (-> (command arg args ...) rest ...))
     ((_ arg command rest ...) (-> (command arg) rest ...))
     ((_ arg) arg)))

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
    (modulo . MOD)
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
    (display . WRITE)))
(define (variable-assigned? var) (vector-ref var 2))
(define (variable-name var) (vector-ref var 1))
;; Inlines primitives, verifies no assigned vars (TODO)
(define (simple-pass ir)
  (match ir
    (#(app #(ref #(var - #f (core primitive)) #t #f ,ann) (,arg) ,ann2)
      `#(primcall SUB (#(quote 0 ,ann) ,(simple-pass arg)) ,ann))
    (#(app #(ref #(var / #f (core primitive)) #t #f ,ann) (,arg) ,ann2)
      `#(primcall DIV (#(quote 1 ,ann) ,(simple-pass arg)) ,ann))
    (#(app #(ref #(var ,name #f (core primitive)) #t #f ,ann) ,args ,ann2)
      (guard (assq name primcalls))
      `#(primcall ,(cdr (assq name primcalls)) ,(map simple-pass args) ,ann))
    (,else (cont-pass ir simple-pass))))

;; TODO: more performant boxing: remember we must store/zero all fields before another alloc.
(define (assignment-conversion ir)
  (let ((counter 0))
    (define (fresh-box var)
      (set! counter (+ counter 1))
      (vector 'var
              (string->symbol (string-append (symbol->string (variable-name var))
                                             "-box"
                                             (number->string counter)))
              #f
              #f))

    (define (convert expr boxes)
      (match expr
        (#(ref ,var ,global ,mutable ,ann)
          (cond
            ((assq var boxes) =>
               (lambda (box)
                 `#(primcall LOAD (#(ref ,(cdr box) #f #t #f) #(quote 0 ,ann)) ,ann)))
            (else expr)))

        (#(set! ,var ,exp ,global? ,ann)
          (let ((new-exp (convert exp boxes)))
            (cond
              ((assq var boxes) =>
                 (lambda (box)
                   `#(primcall STORE (#(ref ,(cdr box) #f #t #f) ,new-exp #(quote 0 ,ann)) ,ann)))
              (else `#(set! ,var ,new-exp ,global? ,ann)))))

        (#(lambda ,cases ,ann)
          (let ((new-cases
                   (map (lambda (clause)
                          (let* ((args (car clause))
                                 (body (cadr clause))
                                 (arg-list (to-proper args))
                                 (boxed-args (filter variable-assigned? arg-list))
                                 (new-boxes (map (lambda (v) (cons v (fresh-box v))) boxed-args))
                                 (new-body (convert body (append new-boxes boxes)))
                                 (body*
                                    (fold-right (lambda (b body)
                                                  `#(let ((,(cdr b)
                                                             #(primcall ALLOC
                                                                        (#(quote 24 ,ann)
                                                                         #(quote 3 ,ann))
                                                                        ,ann)))
                                                      #(begin
                                                         (#(primcall STORE
                                                                     (#(ref ,(cdr b) #f #t #f)
                                                                      #(ref ,(car b) #f #t #f)
                                                                      #(quote 0 ,ann))
                                                                     ,ann)
                                                          #(primcall STORE
                                                                     (#(ref ,(cdr b) #f #t #f)
                                                                      #(quote 0 ,ann)
                                                                      #(quote 1 ,ann))
                                                                     ,ann)
                                                          ,body)
                                                         ,ann)
                                                      ,ann))
                                                new-body
                                                new-boxes)))
                            (list args (if (null? new-boxes) new-body body*))))
                        cases)))
            `#(lambda ,new-cases ,ann)))

        (,else (cont-pass expr (lambda (child) (convert child boxes))))))

    (convert ir '())))

(define (recover-let ir)
  (match ir
    (#(app #(lambda ((,args ,body)) ,lambda-ann) (,params ___) ,app-ann)
      (guard (list? args) (= (length args) (length params)))
      (if (null? params)
          (recover-let body)
          `#(let
             ,(map list args (map recover-let params))
             ,(recover-let body)
             ,lambda-ann)))
    ;; TODO: the rest-args cases
    ;; ((call (lambda (case (,first ___ . ,rest) ,body)) ,params ___)
    ;;   (guard (not (null? rest)) (<= (length first) (length params)))
    ;;   (let ((params (recover-let params))
    ;;         (first-params (take params (length first)))
    ;;         (rest-params (drop params (length first))))
    ;;     `(let
    ;;       (,@(map list first first-params) (,rest (call (lookup list) ,@rest-params)))
    ;;       ,(recover-let body))))
    ;; ((call (lambda (case ,arg ,body)) ,params ___)
    ;;   (guard (symbol? arg))
    ;;   `(let ((,arg (call (lookup list) ,@(map recover-let params))))
    ;;      ,(recover-let body)))
    (,else (cont-pass ir recover-let))))

;; adds name field to lambdas.
(define (name-lambdas ir)
  (define (name-lambdas-int ir cur)
    (define (name-cases cases name)
      (map (lambda (clause) (list (car clause) (name-lambdas-int (cadr clause) name)))
           cases))
    (define (name-lambdas ir)
      (match ir
        (#(define ,var #(lambda ,cases ,lam-ann) ,define-ann)
          (let ((name (symbol->string (vector-ref var 1))))
            `#(define ,var #(nlambda ,name ,(name-cases cases name) ,lam-ann) ,define-ann)))
        (#(lambda ,cases ,lam-ann)
          (let ((name (string-append cur "-anon")))
            `#(nlambda ,name ,(name-cases cases name) ,lam-ann)))
        ;; TODO more names.
        ;; ((set! ,var (lambda ,(name-lambdas-int cases) ___))
        ;;  `(set! ,var (nlambda ,(symbol->string var) ,cases ___)))
        ;; ((fix ,vars (lambda ,(name-lambdas-int cases) ___) ___ ,(name-lambdas-int fix-body))
        ;;  (let ((names (map symbol->string vars)))
        ;;    `(fix ,vars (nlambda ,names ,cases ___) ___ ,fix-body)))
        (,else (cont-pass ir name-lambdas))))
    (name-lambdas ir))
  (name-lambdas-int ir "REPL"))

;; Add  fix (i.e. letrec*) to all.
(define (fix-all ir)
  ;; (display "fix-all:")
  ;; (display ir)
  ;; (newline)
  (match ir
    ;; Don't need to run on already-fixed things.
    (#(letrec* ((,vars #(nlambda ,name ,cases ,lam-ann) ,unused-ann) ___)
        ,letrec-body
        ,letrec-ann)
      (let ((bindings
               (omap (var name cases lam-ann unused-ann)
                     (vars name cases lam-ann unused-ann)
                     (let ((new-cases
                              (map (lambda (clause) (list (car clause) (fix-all (cadr clause))))
                                   cases)))
                       `(,var #(nlambda ,name ,new-cases ,lam-ann) ,unused-ann)))))
        `#(letrec* ,bindings ,(fix-all letrec-body) ,letrec-ann)))
    (#(nlambda ,name ,cases ,ann)
      (let ((tmp (vector 'var (string->symbol name) #f #f)))
        (let ((new-cases
                 (map (lambda (clause) (list (car clause) (fix-all (cadr clause)))) cases)))
          `#(letrec* ((,tmp #(nlambda ,name ,new-cases ,ann) #f)) #(ref ,tmp #f #f #f) #f))))
    (,else (cont-pass ir fix-all))))

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
                 (closure-vars (omap _ vars `#(var clo #f #f)))
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

(define (fits-in-int64 value)
  (and (integer? value)
       (exact? value)
       (<= (- (expt 2 63)) value (- (expt 2 63) 1))))

(define (normalize-const datum)
  (cond
    ((annotation? datum) (normalize-const (annotation-sexp datum)))
    ((syntax? datum) (normalize-const (syntax->datum datum)))
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
                    (begin (add-op fun `(LOOKUP ,top ,(add-const fun (variable-name var)))) top))))
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
      (add-op fun `(DEFINE ,exp ,(add-const fun (variable-name var))))
      (finish exp))
    (#(set! ,var ,(compile-cont exp) #t ,ann)
      (add-op fun `(DEFINE ,exp ,(add-const fun (variable-name var))))
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

(define (fixnum? c) (and (integer? c) (exact? c) (fits-in-int64 c)))
(define (flonum? c) (and (inexact? c) (real? c)))
(define (heap-obj? c)
  (or (string? c)
     (symbol? c)
     (flonum? c)
     (pair? c)
     (vector? c)
     (fun? c)
     (const-closure? c)))

(define (obj-tag o)
  (cond
    ((flonum? o) flonum-tag)
    ((symbol? o) symbol-tag)
    ((pair? o) cons-tag)
    ((vector? o) vector-tag)
    ((const-closure? o) closure-tag)
    (else ptr-tag)))

(define (encode-immediate o)
  (cond
    ((fixnum? o) (* 8 o))
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
    ((flonum? o) (w32 flonum-tag) (w32 0) (writer 'double o))
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
      (w64 dead-tag)
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

(define (emit-image objects canon)
  (define offs (make-hash-table eq?))
  (define pos 0)
  (define (pass1 type val)
    (case type
      ((u8) (set! pos (+ pos 1)))
      ((u16) (set! pos (+ pos 2)))
      ((u32) (set! pos (+ pos 4)))
      ((u64 double word) (set! pos (+ pos 8)))
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

(define (debug-print ir) (display (ir->sexp ir)) (newline) ir)

(define (compile-file file)
  (define empty-library-name (string->symbol ""))
  (define (read-forms path)
    (let ((port (open-input-file path)))
      (let ((forms (read-file port))) (close-input-port port) forms)))
  (define (read-forms-from-string str)
    (let ((port (open-input-string str)))
      (let ((forms (read-file port))) (close-input-port port) forms)))
  (define default-import-forms
    (read-forms-from-string "(import (scheme base)\n               (scheme case-lambda)\n               (scheme char)\n               (scheme complex)\n               (scheme cxr)\n               (scheme eval)\n               (scheme file)\n               (scheme inexact)\n               (scheme lazy)\n               (scheme load)\n               (scheme process-context)\n               (scheme read)\n               (scheme repl)\n               (scheme time)\n               (scheme write)\n               (scheme r5rs))"))
  (define (form-sexp form) (if (annotation? form) (annotation-sexp form) form))
  (define (import-form? form)
    (let ((sexp (form-sexp form))) (and (pair? sexp) (eq? (car sexp) 'import))))
  (define (ensure-leading-import forms)
    (if (and (pair? forms) (import-form? (car forms)))
        forms
        (append default-import-forms forms)))
  (parameterize ((funs (make-funs-list)))
    (let ((out (open-binary-output-file (string-append file ".bc")))
          (runtime-forms (read-forms "runtime.scm"))
          (input-forms (ensure-leading-import (read-forms file))))
      (let* ((lowered
                (-> `#(begin
                        ,(append (expand-program runtime-forms empty-library-name #f)
                                 (expand-program input-forms 'REPL #t))
                        #f)
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
        (add-op main `(HALT 0))
        (add-fun main)

        (let* ((all-funs (get-funs)) (roots (cons main all-funs)))
          (let*-values (((objects canon) (collect-objects roots))
                        ((image offs) (emit-image objects canon)))
            (for-each print-bc all-funs)
            (string-for-each (lambda (c) (write-u8 (char->integer c) out)) "HAWK")
            (write-uint 0 8 out)
            (write-uint (bytevector-length image) 8 out)
            (write-uint (+ (hash-table-ref offs (hash-table-ref canon main)) ptr-tag)
                        8
                        out)
            (write-bytevector image out)))
        (close-output-port out)))))

(display "Compiling:")
(display (cdr (command-line)))
(newline)
(for-each compile-file (cdr (command-line)))
