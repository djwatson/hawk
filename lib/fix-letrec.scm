(define-record-type binding (make-fix-binding free complex init var) binding?
  (free binding-free)
  (complex binding-complex)
  (init binding-init)
  (var binding-var))

(define-syntax for
   (syntax-rules ()
     ((_ (x ...) (xs ...) body ...) (for-each (lambda (x ...) body ...) xs ...))
     ((_ x xs body ...) (for-each (lambda (x) body ...) xs))))

(define (build-let-internal vars inits body)
  (if (null? vars)
      body
      (build-application (build-lambda (list (list vars body)) #f) inits #f)))

(define (build-fix vars inits body)
  (if (null? vars)
      body
      (let ((binds (map (lambda (var init) `(,var ,init #f)) vars inits)))
        (build-letrec* binds body #f))))

(define (build-set! vars inits body)
  (if (null? vars)
      body
      (begin
        (for var vars (vector-set! var 2 #t))
        (let ((setters (map (lambda (var init) (build-set var init #f #f)) vars inits)))
          (build-begin (append setters (list body)) #f)))))

(define (to-proper lst)
  (if (null? lst)
      '()
      (if (pair? lst) (cons (car lst) (to-proper (cdr lst))) (list lst))))

(define (tarjan-scc graph)
  (let ((index 0) (indices '()) (lowlinks '()) (on-stack '()) (result '()))
    (define (update-lowlink v link)
      (let ((cur (assq v lowlinks)))
        (if cur (set-cdr! cur link) (set! lowlinks (cons (cons v link) lowlinks)))))

    (define (strongconnect v)
      (set! indices (cons (cons v index) indices))
      (set! lowlinks (cons (cons v index) lowlinks))
      (set! index (+ index 1))
      (set! on-stack (cons v on-stack))

      (for w (assq v graph)
        (let ((w-index (assq w indices)))
          (if (not w-index)
              (begin
                (strongconnect w)
                (update-lowlink v (min (cdr (assq v lowlinks)) (cdr (assq w lowlinks)))))
              (when (memq w on-stack)
                (update-lowlink v (min (cdr (assq v lowlinks)) (cdr (assq w indices))))))))

      (when (= (cdr (assq v lowlinks)) (cdr (assq v indices)))
        (let loop ((scc '()))
          (let ((w (car on-stack)))
            (set! on-stack (cdr on-stack))
            (if (eq? v w) (set! result (cons (cons v scc) result)) (loop (cons w scc)))))))

    (for v (map car graph) (unless (assq v indices) (strongconnect v)))

    result))

(define-syntax omap
   (syntax-rules ()
     ((_ (x ...) (xs ...) body ...) (map (lambda (x ...) body ...) xs ...))
     ((_ x xs body ...) (map (lambda (x) body ...) xs))))

(define-syntax with-fix-values
   (syntax-rules ()
     ((_ (free complex expr assigned) form body ...)
      (call-with-values (lambda () form)
                        (lambda (free complex expr assigned) body ...)))))

;; Return (values free complex expr assigned)
(define (%fix-letrec expr)
  ;; (display "Fix-letrec:\n")
  ;; (display expr)
  ;; (newline)
  (define (fix-many es)
    (let loop ((es es) (free '()) (complex '()) (exprs '()) (assigned '()))
      (if (null? es)
          (values (reverse free) (reverse complex) (reverse exprs) (reverse assigned))
          (with-fix-values (f c e a)
                           (%fix-letrec (car es))
                           (loop (cdr es)
                                 (cons f free)
                                 (cons c complex)
                                 (cons e exprs)
                                 (cons a assigned))))))
  (define (fix-letrec*-new-body bindings bind-map scc body-expr not-assigned-lambda?)
    (fold-right (lambda (scc expr)
                  (if (= 1 (length scc))
                      (let ((bind (cdr (assq (car scc) bind-map))))
                        (cond
                          ((not-assigned-lambda? bind)
                            (build-fix (list (binding-var bind)) (list (binding-init bind)) expr))
                          ((not (memq (binding-var bind) (binding-free bind)))
                            (build-let-internal (list (binding-var bind))
                                                (list (binding-init bind))
                                                expr))
                          (else
                            (build-let-internal (list (binding-var bind))
                                                (list (build-void #f))
                                                (build-set! (list (binding-var bind))
                                                            (list (binding-init bind))
                                                            expr)))))
                      ;; Multi-scc case
                      (let-values (((unset set)
                                      (partition not-assigned-lambda?
                                                 (omap var scc (cdr (assq var bind-map))))))
                        (let ((seto (filter (lambda (bind) (memq bind set)) bindings)))
                          (build-let-internal (map binding-var seto)
                                              (make-list (length seto) (build-void #f))
                                              (build-fix (map binding-var unset)
                                                         (map binding-init unset)
                                                         (build-set! (map binding-var seto)
                                                                     (map binding-init seto)
                                                                     expr)))))))
                body-expr
                (reverse scc)))
  (define (fix-letrec*-result vars init-free init-complex init-expr init-assigned body-free
           body-complex body-expr body-assigned)
    (let* ((assigned (set-union* (cons body-assigned init-assigned)))
           (bindings
              (omap (free complex expr var)
                    (init-free init-complex init-expr vars)
                    (make-fix-binding free complex expr var)))
           (deps
              (let loop ((bindings bindings) (deps '()) (last-complex #f))
                (if (pair? bindings)
                    (let* ((binding (car bindings))
                           (depend (filter (lambda (x) (memq x vars)) (binding-free binding)))
                           (depend*
                              (if (and (or (binding-complex binding)
                                          ;; If the binding is complex, *or*
                                          ;; it is a variable reference to an assigned var,
                                          ;; and a letrec*, then we need to add an ordering constraint.
                                          (and (ir-reference? (binding-init binding))
                                               (memq (ir-reference-var (binding-init binding))
                                                     assigned)))
                                       last-complex)
                                  (lset-union eq? (list last-complex) depend)
                                  depend)))
                      (loop (cdr bindings)
                            (alist-cons (binding-var binding) depend* deps)
                            (if (binding-complex binding) (binding-var binding) last-complex)))
                    deps)))
           ;; Preserve later bindings for duplicate vars (e.g. internal define rewriting).
           (bind-map (map cons (reverse vars) (reverse bindings)))
           (scc (tarjan-scc deps))
           (not-assigned-lambda?
              (lambda (bind)
                (and (ir-lambda? (binding-init bind))
                     (not (memq (binding-var bind) assigned)))))
           (new-body
              (fix-letrec*-new-body bindings bind-map scc body-expr not-assigned-lambda?)))
      (values (lset-difference eq? (set-union* (cons body-free init-free)) vars)
              (or (or* init-complex) body-complex)
              new-body
              assigned)))
  (cond
    ((ir-begin? expr)
      (with-fix-values (free complex exprs assigned)
                       (fix-many (ir-begin-exps expr))
                       (values (set-union* free)
                               (or* complex)
                               (build-begin exprs (ir-begin-ann expr))
                               (set-union* assigned))))
    ((ir-conditional? expr)
      (let-values (((test-free test-complex test-expr test-assigned)
                      (%fix-letrec (ir-conditional-test expr)))
                   ((true-free true-complex true-expr true-assigned)
                      (%fix-letrec (ir-conditional-then expr)))
                   ((false-free false-complex false-expr false-assigned)
                      (%fix-letrec (ir-conditional-else expr))))
        (values (lset-union eq? test-free true-free false-free)
                (any (lambda (x) x) (list test-complex true-complex false-complex))
                (build-conditional test-expr true-expr false-expr (ir-conditional-ann expr))
                (lset-union eq? test-assigned true-assigned false-assigned))))
    ((ir-assignment? expr)
      (with-fix-values (free complex exp assigned)
                       (%fix-letrec (ir-assignment-exp expr))
                       (values (lset-union eq? (list (ir-assignment-var expr)) free)
                               #t
                               (build-set (ir-assignment-var expr)
                                          exp
                                          (ir-assignment-global? expr)
                                          (ir-assignment-ann expr))
                               (lset-union eq? (list (ir-assignment-var expr)) assigned))))
    ((ir-define? expr)
      (with-fix-values (free complex exp assigned)
                       (%fix-letrec (ir-define-exp expr))
                       (values (lset-union eq? (list (ir-define-var expr)) free)
                               #t
                               (build-define (ir-define-var expr) exp (ir-define-ann expr))
                               assigned)))
    ((ir-letrec*? expr)
      (let* ((letrec-bindings (ir-letrec*-bindings expr))
             (vars (map car letrec-bindings)))
        (with-fix-values (init-free init-complex init-expr init-assigned)
                         (fix-many (map cadr letrec-bindings))
                         (with-fix-values (body-free body-complex body-expr body-assigned)
                                          (%fix-letrec (ir-letrec*-body expr))
                                          (fix-letrec*-result vars
                                                              init-free
                                                              init-complex
                                                              init-expr
                                                              init-assigned
                                                              body-free
                                                              body-complex
                                                              body-expr
                                                              body-assigned)))))
    ((ir-lambda? expr)
      (let ((cases (ir-lambda-cases expr)))
        (with-fix-values (free complex expr2 assigned)
                         (fix-many (map cadr cases))
                         (let ((args-list (map car cases)))
                           (values (set-union* (omap (args free)
                                                     (args-list free)
                                                     (lset-difference eq? free (to-proper args))))
                                   #f
                                   (build-lambda (omap (args expr2)
                                                       (args-list expr2)
                                                       `(,args ,expr2))
                                                 (ir-lambda-ann expr))
                                   (set-union* assigned))))))
    ((ir-quote? expr) (values '() #f expr '()))
    ((ir-void? expr) (values '() #f expr '()))
    ((ir-primcall? expr)
      (with-fix-values (free complex exprs assigned)
                       (fix-many (ir-primcall-args expr))
                       (values (set-union* free)
                               #t
                               (build-primcall (ir-primcall-name expr) exprs (ir-primcall-ann expr))
                               (set-union* assigned))))
    ((ir-application? expr)
      (with-fix-values (ffree fcomplex fexpr fassigned)
                       (%fix-letrec (ir-application-fun expr))
                       (with-fix-values (free complex exprs assigned)
                                        (fix-many (ir-application-args expr))
                                        (values (set-union* (cons ffree free))
                                                #t
                                                (build-application fexpr
                                                                   exprs
                                                                   (ir-application-ann expr))
                                                (set-union* (cons fassigned assigned))))))
    ((ir-reference? expr) (values `(,(ir-reference-var expr)) #f expr '()))
    (else (error "bad expr in fix-letrec:" expr))))

(define (set-union* set*) (apply lset-union eq? set*))

(define (or* obj*) (and (not (null? obj*)) (or (car obj*) (or* (cdr obj*)))))

(define (fix-letrec expr)
  (let-values (((free complex expr assigned) (%fix-letrec expr)))
    ;; (display "Fix done:\n")
    ;; (display expr)
    ;; (newline)
    ;; (display (ir->sexp expr))
    ;; (newline)
    expr))
