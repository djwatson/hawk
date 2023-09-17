;; Map including improper
(define (imap f l)
  (if (null? l) 
      '()
      (if (atom? l)
	  (f l)
	  (cons (f (car l)) (imap f (cdr l))))))

(define (improper? l)
  (if (null? l) #f
      (if (atom? l) #t
	  (improper? (cdr l)))))

(define (to-proper l)
  (if (null? l) '()
      (if (atom? l) (list l) 
	  (cons (car l) (to-proper (cdr l))))))

;;(define (atom? e) (not (pair? e)))

(define gensym-var 0)
(define (compiler-gensym . s)
  (let ((sym (if (pair? s) (car s) 'gensym)))
    (set! gensym-var (+ 1 gensym-var))
    (string->symbol (string-append "var-" (symbol->string sym) "-" (number->string gensym-var)))))


;; Change ((lambda ..) ...) to
;; (let (...) ...)
(define (optimize-direct c)
  (define (sexp-direct f)
    (define params (second (first f)))
    (define args (cdr f))
    (define body (map sexp (cddr (first f))))
    (if (and (pair? params) (not (improper? params)))
	`(let ,(map list params args) ,@body)
	`((lambda ,params ,@body) ,@args)))
  (define (sexp f)
    (if (not (pair? f))
	f
	(case (car f)
	  ((quote) f)
	  (else
	   (if (and (pair? (car f)) (eq? 'lambda (caar f)))
	       (sexp-direct f)
	       (imap sexp f))))))
  (imap sexp c))

;; At this point, 'letrec' is fixed and only contains lambdas,
;; and 'let' hasn't appeared yet, so we only have to add bindings for lambda.
(define (find-assigned f bindings)
  (if (atom? f)
      '()
      (case (car f)
	((set!) (if (memq (second f) bindings) (list (second f)) '()))
	((lambda) (find-assigned (cddr f) (union bindings (to-proper (second f)))))
	((quote) '())
	(else (fold union '() (imap (lambda (f) (find-assigned f bindings)) f))))))
(define (assignment-conversion c)
  (define (convert-assigned f assigned boxes)
    ;;(display (format "Convert assigned f ~a assigned ~a boxes ~a\n" f assigned boxes))
    (if (atom? f)
	(if (assoc f boxes)
	    `($unbox ,(cdr (assoc f boxes)))
	    f)
	(case (car f)
	  ((set!)
	   (let ((value (convert-assigned (third f) assigned boxes)))
	     (if (memq (second f) assigned)
		       `($set-box! ,(cdr (assq (second f) boxes)) ,value)
		       `(set! ,(second f) ,value))))
	  ((lambda)
	   (let* ((new-boxes (filter-map
			 (lambda (x)
			   (if (memq x assigned)
			       (cons x (compiler-gensym x))
			       #f))
			 (to-proper (second f))))
		  (boxes (append new-boxes boxes)))
	     (if (null? new-boxes)
		 `(lambda ,(second f)
		    ,@(imap (lambda (x) (convert-assigned x assigned boxes)) (cddr f)))
		 `(lambda ,(second f)
		    (let
			,(map (lambda (x) `(,(cdr x) ($box ,(car x)))) new-boxes)
		      ,@(imap (lambda (x) (convert-assigned x assigned boxes)) (cddr f)))))))
	  ((quote) f)
	  (else (imap (lambda (a) (convert-assigned a assigned boxes)) f)))))
  (define assigned (find-assigned c '()))
  ;;(display (format "Assigned: ~a\n" assigned))
  (convert-assigned c assigned '()))

;; TODO also case-lambda?
(define (fix-letrec-specific sexp)
  (define assigned (find-assigned sexp (map car (second sexp))))
  (let*
      ((vars (map car (cadr sexp)))
       (bindings (map fix-letrec (map cadr (cadr sexp))))
       (body (fix-letrec (cddr sexp)))
       (fixed (filter-map (lambda (v b)
			    (if
			     (and (pair? b) (eq? 'lambda (car b))
				  (not (memq v assigned)))
			     (list v b) #f))
			  vars bindings)  )
       (set (filter (lambda (v) (not (member v (map car fixed)))) vars))
       (tmp (map compiler-gensym set))
       (setters (map (lambda (s t) `(set! ,s ,t)) set tmp))
       (set-bindings (filter-map (lambda (v b)
				   (if (not (member v (map car fixed)))
				       ;; CONS here, because some default values could be #f.
				       (cons b #t)
				       #f)) vars bindings)))
    (cond
     ((and (pair? set) (pair? fixed))
      `((lambda ,set
	  (letrec ,fixed
	    ((lambda ,tmp
	       (begin
		 ,@setters
		 ,@body))
	     ,@(map car set-bindings))
	    )) ,@(map (lambda (unused) #f) set)))
      ((pair? set)
       `((lambda ,set
	   ((lambda ,tmp
	      (begin
		,@setters
		,@body))
	    ,@(map car set-bindings)))
	 ,@(map (lambda (unused) #f) set)))
      ((pair? fixed)
       `(letrec ,fixed
	  ,@body))
      (else #f))))

(define (fix-letrec sexp)
  (if (pair? sexp)
      (case (car sexp)
	((quote) sexp)
	((letrec) (fix-letrec-specific sexp))
	(else
	 (imap fix-letrec sexp)))
      sexp))


;; TODO: We currently always call through closures.
;;       letrec in particular could analyze for direct calls.
;; TODO: We could also then drop closure vars for recursive procedures
;;       that otherwise don't need closures.
(define (closure-conversion sexp)
  (define (find-free f bindings)
    (if (atom? f)
	(if (memq f bindings) (list f) '())
	(case (car f)
	  ((quote) '())
	  (else (fold union '() (imap (lambda (f) (find-free f bindings)) f))))))
  (define (substitute-free f bindings closure-var self)
    (if (atom? f)
	(if (assq f bindings) `($closure-get ,closure-var ,(cdr (assq f bindings)))
	    ;; Any self-references for letrec go to the closure-var
	    (if (and self (eq? self f))
		closure-var
		f))
	(case (car f)
	  ((quote) f)
	  (else (imap (lambda (f) (substitute-free f bindings closure-var self)) f)))))
  (define (cc f bindings)
    (if (atom? f)
	f
	(case (car f)
	  ((let)
	   `(let ,(map (lambda (b) (list (car b) (cc (second b) bindings))) (second f))
	      ,@(map (lambda (s) (cc s (union (map car (second f)) bindings))) (cddr f))))
	  ;; TODO merge this in to lambda handling?
	  (($case)
	   `($case ,(second f)
		   ,@(map (lambda (s) (cc s (if (pair? (to-proper (second f)))
						(union (to-proper (second f)) bindings) bindings))) (cddr f))))
	  (($loop)
	   `($loop ,(second f)
		   ,@(map (lambda (s) (cc s (if (pair? (to-proper (second f)))
						(union (to-proper (second f)) bindings) bindings))) (cddr f))))
	  ((letrec)
	   (let* ((var-names (map first (second f)))
		  ;; Bindings including the letrec-names
		  (letrec-bindings  (union var-names bindings))
		  ;; Bindings including the lambda variables, for recursing and closing 
		  ;; nested letrec/lambdas.
		  (new-bindings  (fold union letrec-bindings (map (lambda (x) (to-proper (caddr (cadr x)))) (second f))))
		  (closures (map (lambda (x) (compiler-gensym 'closure)) (second f)))
		  (free-vars (map (lambda (f)
				    (difference (find-free (second f) letrec-bindings) (list (first f))))
				  (second f)))
		  (free-bind (map (lambda (free) (map cons free (iota (length free)))) free-vars))
		  (bodies (map (lambda (f bindings closure)
				 (let ((func (second f)))
				   (define closed-body (map (lambda (f) (cc f new-bindings)) (cdddr func)))
				   `(named-lambda ,(second func) ,(third func) ,@(substitute-free closed-body bindings closure (first f)))))
			       (second f) free-bind closures)))
	     `(let ,(map (lambda (v body closure free)
			   `(,v ($closure (named-lambda ,(second body) ,(cons closure (third body)) ,@(cdddr body))
					  ;; Set empty references to letrec's vars.
					  ,(length free))))
			 (map car (second f)) bodies closures free-vars)
		;; Now bind any group references
		(begin
		  ,@(apply append (map (lambda (x bound)
					 (map (lambda (v)
						       `($closure-set ,x ,(car v) ,(cdr v)))
						     bound))
				       var-names free-bind))
		  ,@(map (lambda (f) (cc f new-bindings)) (cddr f))))))
	  ((quote) f)
	  ((named-lambda)
	   (let* (
		  (new-bindings (union (to-proper (third f)) bindings))
		  (body (cc (cdddr f) new-bindings))
		  (free-vars (find-free body bindings))
		  (free-bind (map cons free-vars (iota (length free-vars))))
		  (closure-var (compiler-gensym 'closure))
		  (cr (compiler-gensym 'cr))
		  (new-body (substitute-free body free-bind closure-var #f))
		  (cnt 0))
	     ;;(dformat "FOUND FREE: ~a\n" free-vars)
	     ;;(dformat "Closure vars ~a\n" (+ 1 (length free-vars)))
	     `(let ((,cr ($closure (named-lambda ,(second f) ,(cons closure-var (third f)) ,@new-body)
				   ,(+ 1 (length free-vars)))))
		(begin
		  ,@(map-in-order (lambda (var) (define res `($closure-set ,cr ,var ,cnt)) (inc! cnt) res) free-vars )
		  ,cr))))
	  (else (imap (lambda (f) (cc f bindings)) f)))))
  (map (lambda (f) (cc f '())) sexp))

(define (case-insensitive s)
  (if (pair? s)
      (imap case-insensitive s)
      (if (symbol? s)
	  (string->symbol (list->string (map char-downcase (string->list (symbol->string s)))))
	  s)))

;; Alexpander currently doesn't fully alpha-rename.
(define (alpha-rename f)
  (define (rename f bindings)
    (if (atom? f)
	(if (and (symbol? f) (assoc f bindings))
	    (cdr (assoc f bindings))
	    f)
	(case (car f)
	  ;; Being careful about rest arguments...
	  ((lambda) (let* ((params (second f))
			   (newbind (imap compiler-gensym params))
			   (newenv (append (map cons (to-proper params) (to-proper newbind)) bindings)))
		      `(lambda ,newbind
			 ,@(map (lambda (f) (rename f newenv)) (cddr f)))))
	  ((quote) f)
	  (else (imap (lambda (f) (rename f bindings)) f)))))
  (imap (lambda (f) (rename f '())) f))
;; TODO all of these need error/arg cnt checking.
(define (integrate-r5rs f)
  (define (integrate f)
    (if (atom? f) f
	(case (car f)
	  ;; TODO cleanup.  lol.
	  ((+ - * /) (if (= 3 (length f))
			       (cons (string->symbol (string-append "$" (symbol->string (car f)))) (imap integrate (cdr f)))
			       (let* ((sym (string->symbol (string-append "$" (symbol->string (car f))))))
				      (if (> (length f) 3)
					  `(,sym (,sym
						  ,(integrate (second f))
						  ,(integrate (third f)))
						 ,(if (> (length (cdddr f)) 1)
						      (integrate (cons (car f) (cdddr f)))
						      (integrate (cadddr f))))
					  (imap integrate f)))))
	  ;; TODO could make this n-ary
	  ((< = > <= >=) (if (= 3 (length f))
			     (cons (string->symbol (string-append "$" (symbol->string (car f)))) (imap integrate (cdr f)))
			     (imap integrate f)))
	  ((car cdr set-car! set-cdr! cons vector-ref vector-length string-length string-ref string-set! vector-set! 
		char->integer integer->char symbol->string string->symbol round vector eqv?
		)
	   (cons (string->symbol (string-append "$" (symbol->string (car f)))) (imap integrate (cdr f))))
	  ;; TODO these need a JISEQ?
	  ((quotient) `($exact ($/ ,@(imap integrate (cdr f)))))
	  ((remainder) `($% ,@(imap integrate (cdr f))))
	  ((zero?) `($= ,@(imap integrate (cdr f)) 0))
	  ((eq? char=?) (cons '$eq (imap integrate (cdr f))))
	  ((quote) f)
	  ((if) (if (and (pair? (second f))
			 (eq? (first (second f)) 'not))
		    `(if ,(integrate (second (second f)))
			 ,(if (= 4 (length f)) (integrate (fourth f)) #f)
			 ,(integrate (third f)))
		    (imap integrate f)))
	  ((not) `(if ,(integrate (second f)) #f #t))
	  ((read-char) (if (= 2 (length f))
			   `($read ,(integrate (second f)))
			   `($read current-input-port-internal)))
	  ((write-char) (if (= 3 (length f))
			   `($write ,(integrate (second f)) ,(integrate (third f)))
			   `($write ,(integrate (second f)) current-output-port-internal)))
	  ((pair?) `($guard ,(integrate (second f)) ,cons-tag))
	  ((boolean?) `($guard ,(integrate (second f)) ,literal-tag))
	  ((procedure?) `($guard ,(integrate (second f)) ,closure-tag))
	  ((vector?) `($guard ,(integrate (second f)) ,vector-tag))
	  ((string?) `($guard ,(integrate (second f)) ,string-tag))
	  ((port?) `($guard ,(integrate (second f)) ,port-tag))
	  ((char?) `($guard ,(integrate (second f)) ,char-tag))
	  ((symbol?) `($guard ,(integrate (second f)) ,symbol-tag))
	  ((eof-object?) `($guard ,(integrate (second f)) ,eof-tag))
	  ((flonum? inexact?) `($guard ,(integrate (second f)) ,flonum-tag))
	  ((fixnum? exact? exact-integer?) `($guard ,(integrate (second f)) ,fixnum-tag)) 
	  ((null?) `($guard ,(integrate (second f)) ,nil-tag))
	  ;; TODO add the rest of c*r
	  ((caar) `($car ($car ,(integrate (second f)))))
	  ((cddr) `($cdr ($cdr ,(integrate (second f)))))
	  ((cadr) `($car ($cdr ,(integrate (second f)))))
	  ;((eqv?) `($eq ,(integrate (second f)) ,(integrate (third f)))) ;; TODO flonums
	  (else (imap integrate f)))))
  (imap integrate f))

;; Must run after alpha-conversion
;; Lower individual cases inline.  The code generator will emit CLFUNC/CLFUNCV instead of FUNC/FUNCV for each case,
;; followed by a jump t
(define (lower-case-lambda f)
  (define (test-cases cases)
    (if (pair? cases)
	`($case ,(second (car cases)) (begin ,@(cddr (car cases))) ,(test-cases (cdr cases)))
	`(error "Can't find case for case-lambda")))
  (define (lower-cl f)
    (if (atom? f)
	f
	(if (eq? '$case-lambda (car f))
	    (let* ((lambdas (map lower-cl (cdr f))))
	      `(lambda () ,(test-cases lambdas)))
	    (imap lower-cl f))))
  (imap lower-cl f))

;; Optional loop-detection pass.
(define (lower-loops f)
  (define (no-refs? var f)
    ;;(dformat "no refs ~a ~a\n" var f)
    (if (atom? f)
	(not (eq? f var))
	(fold (lambda (a b) (and (no-refs? var a) b)) #t f)))
  (define (only-tailcalls? var f)
    ;;(dformat "only tailcalls ~a ~a\n" var f)
    (if (atom? f)
	(not (eq? f var))
	(case (car f)
	  ((if) (and (no-refs? var (second f)) (only-tailcalls? var (third f))
		     (or (= 3 (length f)) (only-tailcalls? var (fourth f)))))
	  ((let) (and (no-refs? var (second f)) (only-tailcalls? var (third f))))
	  ((begin) (case (length f)
		     ((1) #t)
		     ((2) (only-tailcalls? var (second f)))
		     (else (and (no-refs? var (second f)) (only-tailcalls? var `(begin ,@(cddr f)))))))
	  ((lambda) (no-refs? var f))
	  (else (if (atom? (car f))
		    (no-refs? var (cdr f))
		    (no-refs? var f))))))
  (define (lower f)
    (if (atom? f)
	f
	(if (and (pair? (first f))
		 (eq? 'letrec (caar f))
		 (= 1 (length (second (car f))))
		 (eq? (caar (second (car f))) (third (car f)))
		 (only-tailcalls? (caar (second (car f))) (third (second (car (second (car f)))))))
	    (begin
	      ;;(dformat "Loopify: ~a\n" f)
	      `($loop ,(second (second (car (second (car f)))))
		      ,(cdr f)
		      ,(caar (second (car f)))
		      ,(lower (third (second (car (second (car f))))))))
	    (if (eq? 'quote (car f)) f
		(imap lower f)))))
  (imap lower f))

(define (name-lambdas f)
  (define (name f cur)
    (if (pair? f)
	(case (car f)
	  ((define)
	   (if (> (length f) 2)
	       (list 'define (second f) (name (third f) (symbol->string (second f))))
	       (imap (lambda (f) (name f cur)) f)))
	  ((lambda) `(named-lambda ,cur ,@(imap (lambda (f) (name f (string-append cur "-lambda"))) (cdr f))))
	  ((quote) f)
	  ;; Letrecs are already fixed and contain only lambdas.
	  ((letrec)
	   (let* ((vars (second f))
		  (named (map (lambda (f) (list (first f) (name (second f) (symbol->string (first f))))) (second f))))
	     `(letrec ,named ,@(imap (lambda (f) (name f cur)) (cddr f)))))
	  (else (imap (lambda (f) (name f cur)) f)))
	f))
  (imap (lambda (f) (name f "repl")) f))