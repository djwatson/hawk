(define-library (r7expand)
  (import (scheme base) (scheme case-lambda) (scheme write) (srfi 1) (builders))
  (export make-toplevel-environment current-toplevel-environment with-toplevel-environment
          install-toplevel-binding! unwrap-syntax identifier=? extend-environment install-expander!
          expand er-macro-transformer make-expander identifier? extend-environment!
          toplevel-environment? current-meta-environment current-use-environment
          make-identifier assq-environment)
  (begin
    (define-record-type environment (make-environment base frame) environment?
      (base enclosing-environment) ;; parent scope, or base name
      (frame environment-frame set-environment-frame!)) ;; ids defined here

    (define (make-toplevel-environment name) (make-environment name '()))

    (define (toplevel-environment? env)
      (not (environment? (enclosing-environment env))))

    (define current-toplevel-environment (make-parameter #f))

    (define (with-toplevel-environment top-env thunk)
      (parameterize ((current-toplevel-environment top-env)) (thunk)))

    (define (assq-environment id env)
      (let ((frame (environment-frame env)))
        (or (assq id frame)
            (cond
              ((toplevel-environment? env)
                (cond
                  ((%identifier? id)
                    (assq-environment (identifier-symbol id) (identifier-environment id)))
                  ((symbol? id)
                    (let ((new-var (generate-variable id (enclosing-environment env))))
                      (set-environment-frame! env (alist-cons id new-var frame))
                      (assq-environment id env)))
                  (else #f)))
              (else (assq-environment id (enclosing-environment env)))))))

    (define (install-toplevel-binding! id name top-env)
      (unless (toplevel-environment? top-env) (error "Not toplevel env"))
      (let ((frame (environment-frame top-env)))
        (set-environment-frame! top-env (alist-cons id name frame))))

    (define-record-type identifier (make-identifier sym env) %identifier?
      (env identifier-environment)
      (sym identifier-symbol))

    (define (identifier? x) (or (symbol? x) (%identifier? x)))

    (define (unwrap-syntax obj)
      (cond
        ((%identifier? obj) (unwrap-syntax (identifier-symbol obj)))
        ((pair? obj) (cons (unwrap-syntax (car obj)) (unwrap-syntax (cdr obj))))
        ((vector? obj) (vector-map unwrap-syntax obj))
        (else obj)))

    (define (identifier=? id1 env1 id2 env2)
      (define (resolve-binding id env)
        (cond
          ((assq-environment id env) => cdr)
          ((%identifier? id)
            (resolve-binding (identifier-symbol id) (identifier-environment id)))
          (else #f)))
      (eq? (resolve-binding id1 env1) (resolve-binding id2 env2)))

    (define (generate-variable id library-name)
      (build-variable (unwrap-syntax id) library-name))

    (define (extend-environment! id env)
      (unless (and (toplevel-environment? env) (symbol? id))
        (let ((frame (environment-frame env)))
          (cond
            ((assq id frame) (error "duplicate binding" id))
            (else
              (let ((var (generate-variable id #f)))
                (set-environment-frame! env (alist-cons id var frame))))))))

    (define (extend-environment ids env)
      (let ((new-env (make-environment env '())))
        (for-each (lambda (id) (extend-environment! id new-env)) ids)
        new-env))

    (define-record-type expander (make-expander transformer environment) expander?
      (transformer expander-transformer)
      (environment expander-environment))

    (define (install-expander! keyword expander env)
      (extend-environment! keyword env)
      (let ((cell (assq-environment keyword env))) (set-cdr! cell expander)))

    (define current-meta-environment (make-parameter #f))
    (define current-use-environment (make-parameter #f))

    (define (with-meta-environment meta-env thunk)
      (parameterize ((current-meta-environment meta-env)) (thunk)))

    (define expand
      (case-lambda
        ((form) (expand form (current-toplevel-environment)))
        ((form env)
          (let ()
            (define (expand-macro expander form env)
              (let ((transformer (expander-transformer expander))
                    (meta-env (expander-environment expander)))
                (with-meta-environment
                  meta-env
                  (lambda ()
                    (parameterize ((current-use-environment env))
                      (transformer form env))))))

            (define (expand-identifier id env)
              (define (binding->reference binding)
                (if (eq? (variable-library-name binding) #f)
                    (build-lexical-reference binding (variable-assigned binding))
                    (build-global-reference binding (variable-assigned binding))))
              (cond
                ((assq-environment id env)
                 =>
                 (lambda (cell)
                   (let ((binding (cdr cell)))
                     (if (variable? binding)
                         (binding->reference binding)
                         binding))))
                (else
                 (expand-identifier (identifier-symbol id)
                                    (identifier-environment id)))))

            (let expand ((form form))
              (cond
                ((identifier? form) (expand-identifier form env))
                ((and (pair? form) (list? form))
                  (let ((e (expand (car form))))
                    (if (and (identifier? (car form)) (expander? e))
                        (expand-macro e form env)
                        (let ((args (map expand (cdr form))))
                          (build-application e args)))))
                ((not (pair? form)) (build-quote form))
                (else (error "invalid expression" form))))))))

    (define (er-macro-transformer proc)
      (lambda (form env)
        (let ((table '()))
          (let ((rename
                   (lambda (x)
                     (cond
                       ((assq x table) => cdr)
                       (else
                         (let ((id (make-identifier x (current-meta-environment))))
                           (set! table (alist-cons x id table))
                           id)))))
                (compare (lambda (x y) (identifier=? x env y env))))
            (expand (proc form rename compare) env)))))))
