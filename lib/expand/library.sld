;;; R7RS expander

;;; toplevel mutable states:
;;; - library-table
;;; - feature-list

;;; TODO
;;; - check import collision
;;; - check if exported symbols are defined

(define-library (library)
  (export expand-library expand-program expand-repl expand-toplevel make-library with-library
          current-library current-directory with-current-directory-from-file resolve-path
          read-file-forms library-paths library-exists? library-import library-export
          feature-list library-spec->normalized-string)
  (import (scheme base) (scheme cxr) (scheme read) (scheme file) (r7expand) (builders)
          (scheme write) (srfi 1))
  (begin
    (define (make-r7rs-toplevel-environment name)
      (make-toplevel-environment name))

    (define-record-type library-object (make-library-object environment exports) library-object?
      (environment library-object-environment)
      (exports library-object-exports set-library-object-exports!))

    (define library-table '())

    (define (assoc-library spec) (assoc spec library-table))

    (define current-library (make-parameter #f))
    (define current-directory (make-parameter "."))
    (define library-paths (make-parameter '()))
    (define autoloaded-library-bodies (make-parameter '()))

    (define (with-library spec thunk)
      (parameterize ((current-library spec))
        (let ((env (library-environment (current-library))))
          (with-toplevel-environment env thunk))))

    (define (library-spec-part->string part)
      (if (symbol? part) (symbol->string part) (number->string part)))

    (define (join-parts parts sep)
      (fold-right (lambda (part acc)
                    (if (string=? acc "") part (string-append part sep acc)))
                  ""
                  parts))

    (define (library-spec->normalized-string spec)
      (join-parts (map library-spec-part->string spec) "."))

    (define make-library
      (let ()
        (define (make-library spec)
          (let ((env (make-r7rs-toplevel-environment spec)))
            (let ((obj (make-library-object env '())))
              (set! library-table (alist-cons spec obj library-table)))))

        make-library))

    (define (library-environment spec)
      (ensure-library-loaded spec)
      (library-object-environment (cdr (assoc-library spec))))

    (define (library-exports spec)
      (ensure-library-loaded spec)
      (library-object-exports (cdr (assoc-library spec))))

    (define (library-exists? spec) (and (assoc-library spec) #t))

    (define (library-spec->relative-file spec)
      (string-append (join-parts (map library-spec-part->string spec) "/") ".sld"))

    (define (join-directory dir rel)
      (cond
        ((string=? dir "") rel)
        ((string=? dir ".") rel)
        ((string=? dir "/") (string-append "/" rel))
        (else (string-append dir "/" rel))))

    (define (load-library-from-file filename)
      (with-current-directory-from-file filename
        (lambda (resolved)
          (let ((forms (read-file-forms resolved)))
            (unless (and (= (length forms) 1)
                         (list? (car forms))
                         (>= (length (car forms)) 2)
                         (eq? (caar forms) 'define-library))
              (error "malformed library file"))
            (expand-library (car forms))))))

    (define (try-autoload-library spec)
      (let* ((rel (library-spec->relative-file spec))
             (filename
               (find (lambda (candidate) (file-exists? candidate))
                     (map (lambda (dir) (join-directory dir rel)) (library-paths)))))
        (and filename
             (let ((library-body (load-library-from-file filename)))
               (autoloaded-library-bodies
                 (append (autoloaded-library-bodies)
                         (list library-body)))
               #t))))

    (define (ensure-library-loaded spec)
      (unless (or (library-exists? spec) (try-autoload-library spec))
        (error "library not found" spec)))

    (define (expand-library form)
      (let ((spec (cadr form)))
        (make-library spec)
        (with-library spec
                      (lambda ()
                        (let ((decls (cddr form)))
                          (let ((forms (append-map interpret-library-declaration decls)))
                            (expand-toplevel forms)))))))

    (define (interpret-library-declaration decl)
      (case (car decl)
        ((begin) (cdr decl))
        ((import) (for-each library-import (cdr decl)) '())
        ((export) (for-each library-export (cdr decl)) '())
        ((cond-expand) (interpret-cond-expand (cdr decl)))
        ((include) (list decl))
        ((include-library-declarations)
          (append-map interpret-library-declarations-file (cdr decl)))))

    (define library-import
      (let ()
        (define (library-import spec)
          (let ((name-map (make-name-map spec)))
            (let ((env (current-toplevel-environment)))
              (for-each (lambda (c) (install-toplevel-binding! (car c) (cdr c) env)) ; TODO redefinition of macros
                        name-map))))

        (define (make-name-map spec)
          (define res
            (case (car spec)
              ((prefix)
                (let ((name-map (make-name-map (cadr spec))))
                  (map (lambda (c)
                         (let ((nickname
                                  (string->symbol (string-append (symbol->string (caddr spec))
                                                                 (symbol->string (car c))))))
                           (cons nickname (cdr c))))
                       name-map)))
              ((only)
                (let ((name-map (make-name-map (cadr spec))))
                  (let ((args (cddr spec)))
                    (map (lambda (v)
                           (let ((res (assq v name-map)))
                             (unless res (error "can't find to import:" v))
                             res))
                         args))))
              ((except)
                (let loop ((name-map (make-name-map (cadr spec))) (args (cddr spec)))
                  (if (null? args)
                      name-map
                      (loop (alist-delete (car args) name-map) (cdr args)))))
              ((rename)
                (let loop ((name-map (make-name-map (cadr spec))) (args (cddr spec)))
                  (map (lambda (c)
                         (let loop ((args (cddr spec)))
                           (cond
                             ((null? args) c)
                             ((eq? (car c) (caar args)) (cons (cadar args) (cdr c)))
                             (else (loop (cdr args))))))
                       name-map)))
              (else
                (let ((exports (library-exports spec)) (env (library-environment spec)))
                  (map (lambda (cell)
                         (let ((nickname (car cell)) (id (cdr cell)))
                           (let ((name (cdr (assq-environment id env)))) `(,nickname . ,name))))
                       exports)))))
          res)

        library-import))

    (define (library-export spec)
      (let-values (((id nickname)
                      (if (symbol? spec) (values spec spec) (values (cadr spec) (caddr spec)))))
        (let ((obj (cdr (assoc-library (current-library)))))
          (let ((exports (library-object-exports obj)))
            (set-library-object-exports! obj (alist-cons nickname id exports))))))

    (define feature-list '())

    (define (interpret-cond-expand clauses) ; follows srfi-0 semantics
      (let loop ((clauses clauses))
        (if (null? clauses)
            (error "unfulfilled cond-expand")
            (let ((c (caar clauses)))
              (if (or (eq? c 'else)
                     (let test ((c c))
                       (if (symbol? c)
                           (memq c feature-list)
                           (case (car c)
                             ((library) (library-exists? (cadr c)))
                             ((not) (not (test (cadr c))))
                             ((and)
                               (let loop ((cs (cdr c)))
                                 (or (null? cs) (and (test (car cs)) (loop (cdr cs))))))
                             ((or)
                               (let loop ((cs (cdr c)))
                                 (and (pair? cs) (or (test (car cs)) (loop (cdr cs))))))))))
                  (append-map interpret-library-declaration (cdar clauses))
                  (loop (cdr clauses)))))))

    (define (absolute-path? filename)
      (and (> (string-length filename) 0) (char=? (string-ref filename 0) #\/)))

    (define (path-directory filename)
      (let loop ((i (- (string-length filename) 1)))
        (cond
          ((< i 0) ".")
          ((char=? (string-ref filename i) #\/) (if (= i 0) "/" (substring filename 0 i)))
          (else (loop (- i 1))))))

    (define (path-prefixed-by-current-directory? filename)
      (let ((dir (current-directory)))
        (and (not (or (string=? dir "") (string=? dir ".") (string=? dir "/")))
             (or (string=? filename dir)
                 (let ((prefix (string-append dir "/")))
                   (and (>= (string-length filename) (string-length prefix))
                        (string=? (substring filename 0 (string-length prefix)) prefix)))))))

    (define (resolve-path filename)
      (cond
        ((absolute-path? filename) filename)
        ((path-prefixed-by-current-directory? filename) filename)
        ((or (string=? (current-directory) "") (string=? (current-directory) "."))
          filename)
        ((string=? (current-directory) "/") (string-append "/" filename))
        (else (string-append (current-directory) "/" filename))))

    (define (with-current-directory-from-file filename thunk)
      (let ((resolved (resolve-path filename)))
        (parameterize ((current-directory (path-directory resolved))) (thunk resolved))))

    (define (read-file-forms filename)
      (call-with-input-file filename
        (lambda (port)
          (let loop ((form (read port)) (acc '()))
            (if (eof-object? form)
                (reverse acc)
                (loop (read port) (cons form acc)))))))

    (define (interpret-library-declarations-file filename)
      (with-current-directory-from-file filename
        (lambda (resolved)
          (append-map interpret-library-declaration (read-file-forms resolved)))))

    (define (expand-program forms namespace)
      (let ((env (make-r7rs-toplevel-environment namespace)))
        (parameterize ((autoloaded-library-bodies '()))
          (with-toplevel-environment env
                                     (lambda ()
                                       (let loop ((forms forms))
                                         (cond
                                           ((null? forms)
                                             (let ((library-bodies (autoloaded-library-bodies)))
                                               (if (null? library-bodies)
                                                   (build-void)
                                                   (build-begin
                                                     (append library-bodies
                                                             (list (build-void)))))))
                                           ((and (pair? (car forms))
                                                 (eq? (caar forms) 'import))
                                             (for-each library-import (cdar forms))
                                             (loop (cdr forms)))
                                           (else
                                             (let ((program-body (expand-toplevel forms))
                                                   (library-bodies (autoloaded-library-bodies)))
                                               (if (null? library-bodies)
                                                   program-body
                                                   (build-begin
                                                     (append library-bodies
                                                             (list program-body)))))))))))))

    (define (expand-repl form env)
      (with-toplevel-environment env
                                 (lambda ()
                                   (parameterize ((autoloaded-library-bodies '()))
                                     (let* ((repl-body
                                              (cond
                                                ((and (list? form) (eq? (car form) 'import))
                                                 (for-each library-import (cdr form))
                                                 (build-void))
                                                (else (expand-toplevel (list form)))))
                                            (library-bodies (autoloaded-library-bodies)))
                                       (if (null? library-bodies)
                                           repl-body
                                           (build-begin (append library-bodies
                                                                (list repl-body)))))))))

    (define expand-toplevel
      (let ()
        (define (ir-begin? form)
          (and (vector? form)
               (> (vector-length form) 0)
               (eq? (vector-ref form 0) 'begin)))

        (define (flatten form)
          (cond
            ((ir-begin? form)
              (append-map flatten (vector-ref form 1)))
            (else (list form))))

        (define (expand-toplevel forms)
          (let ((forms (append-map flatten (map expand forms))))
            (if (= (length forms) 1) (car forms) (build-begin forms))))

        expand-toplevel))))
