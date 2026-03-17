(define-record-type binding (make-binding free complex init var) binding?
  (free binding-free)
  (complex binding-complex)
  (init binding-init)
  (var binding-var))

(define-syntax for
   (syntax-rules ()
     ((_ (x ...) (xs ...) body ...) (for-each (lambda (x ...) body ...) xs ...))
     ((_ x xs body ...) (for-each (lambda (x) body ...) xs))))

(define (build-let vars inits body)
  (if (null? vars) body `#(app #(lambda ((,vars ,body)) #f) ,inits #f)))

(define (build-fix vars inits body)
  (if (null? vars)
      body
      (let ((binds (map (lambda (var init) `(,var ,init #f)) vars inits)))
        `#(letrec* ,binds ,body #f))))

(define (build-set! vars inits body)
  (if (null? vars)
      body
      (begin
        (for var vars (vector-set! var 2 #t))
        (let ((setters (map (lambda (var init) `#(set! ,var ,init #f #f)) vars inits)))
        `#(begin (,@setters ,body) #f)))))

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

;; Return (values free complex expr assigned)
(define (%fix-letrec expr)
  ;; (display "Fix-letrec:\n")
  ;; (display expr)
  ;; (newline)
  (match expr
    (#(begin (,(%fix-letrec free complex expr assigned) ___) ,ann)
      (values (set-union* free)
              (or* complex)
              `#(begin ,expr ,ann)
              (set-union* assigned)))
    (#(if ,(%fix-letrec test-free test-complex test-expr test-assigned)
          ,(%fix-letrec true-free true-complex true-expr true-assigned)
          ,(%fix-letrec false-free false-complex false-expr false-assigned)
          ,ann)
      (values (lset-union eq? test-free true-free false-free)
              (any (lambda (x) x) (list test-complex true-complex false-complex))
              `#(if ,test-expr ,true-expr ,false-expr ,ann)
              (lset-union eq? test-assigned true-assigned false-assigned)))
    (#(set! ,var ,(%fix-letrec free complex expr assigned) ,global? ,ann)
      (values (lset-union eq? (list var) free)
              #t
              `#(set! ,var ,expr ,global? ,ann)
              (lset-union eq? (list var) assigned)))
    (#(define ,var ,(%fix-letrec free complex expr assigned) ,ann)
      (values (lset-union eq? (list var) free)
              #t
              `#(define ,var ,expr ,ann)
              assigned))
    (#(letrec* ((,vars ,(%fix-letrec init-free init-complex init-expr init-assigned) ,ann)
                ___)
        ,(%fix-letrec body-free body-complex body-expr body-assigned)
        ,ann)
      (let* ((assigned (set-union* `(,body-assigned ,@init-assigned)))
             (bindings
                (omap (free complex expr var)
                      (init-free init-complex init-expr vars)
                      (make-binding free complex expr var)))
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
                                            (and (symbol? (binding-init binding))
                                                 (memq (binding-init binding) assigned)))
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
                  (let ((init (binding-init bind)))
                    (and (vector? init)
                         (eq? 'lambda (vector-ref init 0))
                         (not (memq (binding-var bind) assigned))))))
             (new-body
                (fold-right (lambda (scc expr)
                              (if (= 1 (length scc))
                                  (let ((bind (cdr (assq (car scc) bind-map))))
                                    (cond
                                      ((not-assigned-lambda? bind)
                                        (build-fix (list (binding-var bind))
                                                   (list (binding-init bind))
                                                   expr))
                                      ((not (memq (binding-var bind) (binding-free bind)))
                                        (build-let (list (binding-var bind))
                                                   (list (binding-init bind))
                                                   expr))
                                      (else
                                        (build-let (list (binding-var bind))
                                                   (list #(void #f))
                                                   (build-set! (list (binding-var bind))
                                                               (list (binding-init bind))
                                                               expr)))))
                                  ;; Multi-scc case
                                  (let-values (((unset set)
                                                  (partition not-assigned-lambda?
                                                             (omap var
                                                                   scc
                                                                   (cdr (assq var bind-map))))))
                                    ;; Orderer the complex bindings in their occurance in the original form

                                    (let ((seto (filter (lambda (bind) (memq bind set)) bindings)))
                                      ;; (display "SET:") (display (length seto)) (display ":")
                                      ;; (display (map binding-var seto)) (newline)
                                      ;; (display "UNSET:") (display (length unset)) (display ":")
                                      ;; (display (map binding-var unset)) (newline)
                                      ;; (display "DEPS:") (pretty-print (filter-map (lambda (x)
                                      ;; 					       (if (memq (car x) scc)
                                      ;; 						   (filter (lambda (x) (memq x scc)) x)
                                      ;; 						   #f)) deps))
                                      ;; (newline)
                                      (build-let (map binding-var seto)
                                                 (make-list (length seto) #(void #f))
                                                 (build-fix (map binding-var unset)
                                                            (map binding-init unset)
                                                            (build-set! (map binding-var seto)
                                                                        (map binding-init seto)
                                                                        expr)))))))
                            body-expr
                            (reverse scc))))
        ;; (when (> (length deps) 1)
        ;; 	  (display deps) (newline) (newline))
        ;; (display "Tarjan:") (display scc) (newline)
        (values (lset-difference eq? (set-union* `(,body-free ,@init-free)) vars)
                (or (or* init-complex) body-complex)
                new-body
                assigned)))
    (#(lambda ((,args ,(%fix-letrec free complex expr2 assigned)) ___) ,ann)
      (values (set-union* (omap (args free)
                                (args free)
                                (lset-difference eq? free (to-proper args))))
              #f
              `#(lambda ,(omap (args expr2) (args expr2) `(,args ,expr2)) ,ann)
              (set-union* assigned)))
    (#(quote ,x ,ann) (values '() #f expr '()))
    (#(void ,ann) (values '() #f expr '()))

    (#(primcall ,name (,(%fix-letrec free complex expr assigned) ___) ,ann)
      (values (set-union* free)
              #t
              `#(primcall ,name ,expr ,ann)
              (set-union* assigned)))
    (#(app ,(%fix-letrec ffree fcomplex fexpr fassigned)
           (,(%fix-letrec free complex expr assigned) ___)
           ,ann)
      (values (set-union* (cons ffree free))
              #t
              `#(app ,fexpr ,expr ,ann)
              (set-union* (cons fassigned assigned))))
    (#(ref ,var ,global ,mutable ,ann) (values `(,var) #f expr '()))
    (,else expr (error "bad expr in fix-letrec:" expr))))

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
