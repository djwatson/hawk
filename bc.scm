(import (r7rs))
(import (srfi 1)) ;; lists
(import (srfi 17)) ;; generalized-set!
(import (srfi 28)) ;; basic format
(import (srfi 69)) ;; hash-table
(import (srfi 99)) ;; define-record-type
(define-syntax define-getter-with-setter
  (syntax-rules ()
    ((_ getter setter)
     (set! getter (getter-with-setter getter setter)))))

;; TODO reg = free reg set
(define-record-type func-bc #t #t
		    (name) (code) (consts) (reg))
 (define-getter-with-setter func-bc-code func-bc-code-set!)
 (define-getter-with-setter func-bc-consts func-bc-consts-set!)
 (define-getter-with-setter func-bc-reg func-bc-reg-set!)

(define-syntax inc!
  (syntax-rules ()
    ((_ var) (set! var (+ 1 var)))))

(define-syntax push!
  (syntax-rules ()
    ((_ var val) (set! var (cons val var)))))

(define (finish bc tail r)
  ;; TODO reg
  (if tail
      (push! (func-bc-code bc) (list 'RET1 r))
      r))

(define (compile-self-evaluating f bc tail)
  (define r (func-bc-reg bc))
  ;; TODO save len
  (define c (length (func-bc-consts bc)))
  (inc! (func-bc-reg bc))
  (if (and  (number? f) (< (abs f) 30000))
      (push! (func-bc-code bc) (list 'KSHORT r f))
      (begin
	(push! (func-bc-consts bc) f)
	(push! (func-bc-code bc) (list 'KONST r c))))
  (finish bc tail r))

(define (compile-binary f bc env tail)
  (define r1 (compile-sexp (second f) bc env #f))
  (define r2 (compile-sexp (third f) bc env #f))
  (define r (func-bc-reg bc))
  (define op (second (assq (first f) '((+ ADDVV) (- SUBVV)))))
  (inc! (func-bc-reg bc))
  (push! (func-bc-code bc) (list op r r1 r2))
  (finish bc tail r))

(define (compile-if f bc env tail)
  (define r (compile-sexp (second f) bc env #f))
  (define jop (list 'JMP 0))
  (define jop2 (list 'JMP 0))
  (push! (func-bc-code bc) (list 'ISF r))
  (push! (func-bc-code bc) jop)
  (let ((rt (compile-sexp (third f) bc env tail)))
    (when (not tail)
      (push! (func-bc-code bc) jop2))
    ;; TODO len
    (set! (second jop) (length (func-bc-code bc)))
    (let ((rf (compile-sexp (fourth f) bc env tail)))
      (when (not tail)
	(when (not (eqv? rf rt))
	  (push! (func-bc-code bc) `(MOV ,rf ,rt)))
	(set! (second jop2) (length (func-bc-code bc)))
	rt))))

(define (compile-sexp f bc env tail)
  (if (not (pair? f))
      (if (symbol? f)
	  (compile-lookup f bc env tail)
	  (compile-self-evaluating f bc tail))
      (case (car f)
	((define) (compile-define f bc env tail))
	((letrec (compile-letrec f bc env tail)))
	((lambda) (compile-lambda f bc env tail))
	((begin) (compile-sexps (cdr f) bc env tail))
	((if) (compile-if f bc env tail))
	((set!) (compile-set! f bc env tail))
	((quote) (compile-self-evaluating (second f) bc tail))
	((+ -) (compile-binary f bc env tail))
	(else (compile-call f bc env tail)))))

(define (compile-sexps program bc env tail)
  (if (null? (cdr program)) 
    (compile-sexp (car program) bc env tail)
    (begin
      (compile-sexp (car program) bc env #f)
      (compile-sexps (cdr program) bc env tail))))

(define (compile d)
  (define bc (make-func-bc "repl" '() '() 0))
  (compile-sexps d bc '() #t)
  (display-bc bc))

(define (display-bc bc)
  (display (format "~a:\n" (func-bc-name bc)))
  (display "Consts:\n")
  (fold (lambda (a b)
	  (display (format "~a: ~a\n" b a))
	  (+ b 1))
	0 (reverse (func-bc-consts bc)))
  (display "Code:\n")
  (fold (lambda (a b)
	  (display (format "~a: ~a\n" b a))
	  (+ b 1))
	0 (reverse (func-bc-code bc))))

(compile (list (read)))

;; (define-record-type compile-ctx #t #t
;; 		    (memory))
;; (define-getter-with-setter compile-ctx-memory compile-ctx-memory-set!)

;; (define (compile-self-evaluating s)
;;   (build-const s))

;; (define (compile-builtin s ctx env)
;;   (define arg-outputs (map (lambda (s)
;; 			     (compile-sexp s ctx env))
;; 			   (cdr s)))
;;   (define op (build-op-from-inputs (first s) arg-outputs))
;;   (add-node-output op 'scheme))

;; (define (compile-call s ctx env)
;;   (define args (map (lambda (s) (compile-sexp s ctx env)) s))
;;   (define arg-outputs (append args (list (compile-ctx-memory ctx))))
;;   (define op (build-op-from-inputs 'call arg-outputs))
;;   (define call-res (add-node-output op 'scheme))
;;   (define mem-res (add-node-output op 'memory))
;;   (set! (compile-ctx-memory ctx) mem-res)
;;   call-res)

;; (define (env-keys env)
;;   (map first env))

;; ;; See if symbol exists in *any* scope
;; (define (env-exists env symbol)
;;   (assq symbol env))

;; ;; Returns param num, possibly inserted in to current env.
;; (define (env-lookup env symbol)
;;   (define res (assq symbol env))
;;   (if res (cdr res)
;;       ;; Otherwise we have to add a new argument to the env.
;;       (compiler-error "could not find env")))

;; (define (compile-lookup s ctx env)
;;   (if (env-exists env s)
;;       (cdr (env-exists env s))
;;       (let ((lu (build-lookup s (compile-ctx-memory ctx))))
;; 	(set! (compile-ctx-memory ctx) (vector-ref (node-outputs lu) 1))
;; 	(vector-ref (node-outputs lu) 0))))

;; (define (compile-define s ctx env)
;;   (define res (compile-sexp (third s) ctx env))
;;   (let ((def (build-define (second s) res (compile-ctx-memory ctx))))
;;     (set! (compile-ctx-memory ctx) def)
;;     ;; TODO undef
;;     (compile-self-evaluating -1)))

;; (define (compile-if s ctx env)
;;   (define demands (demand-set (cddr s) (env-keys env)))

;;   (define cond (compile-sexp (second s) ctx env))
;;   (define captures (map (lambda (e) (env-lookup env e)) demands))
  
;;   (define sw (build-switch (append (list cond) captures (list (compile-ctx-memory ctx))) 2))
;;   (define true-region (vector-ref (structural-regions sw) 0))
;;   (define false-region (vector-ref (structural-regions sw) 1))

;;   ;; Note region outputs is one longer: 'memory', which isn't in env.
;;   (define true-env (map (lambda (demand capture)
;; 			  (cons demand capture))
;; 			demands (vector->list (node-outputs true-region))))
;;   (define false-env (map (lambda (demand capture)
;; 			  (cons demand capture))
;; 			demands (vector->list (node-outputs false-region))))
;;   (define true-mem (vector-last (node-outputs true-region)))
;;   (define false-mem (vector-last (node-outputs false-region)))

;;   (set! (compile-ctx-memory ctx) true-mem)
;;   (let ((true (compile-sexp (third s) ctx true-env)))
;;     (region-add-result true-region true)
;;     (region-add-result true-region (compile-ctx-memory ctx)))
  
;;   (set! (compile-ctx-memory ctx) false-mem)
;;   (let ((false (compile-sexp (fourth s) ctx false-env)))
;;     (region-add-result false-region false)
;;     (region-add-result false-region (compile-ctx-memory ctx)))
  
;;   ;;output
;;   (let ((res (add-node-output sw 'scheme)))
;;     (set! (compile-ctx-memory ctx) (add-node-output sw 'memory))
;;     res))

;; (define (compile-lambda name s ctx env)
;;   (define demands (demand-set (list s) (env-keys env)))
;;   (define captures (map (lambda (e) (env-lookup env e)) demands))
;;   (define params (append (second s) (list (cons 'memory 'memory))))
;;   (define f (build-func name (map (lambda (n) (if (pair? n) n (cons n 'scheme))) params) captures))
;;   (define region (body-region f))

;;   (define new-env (filter-map (lambda (sym output)
;; 				(if (eq? 'memory (node-output-type output))
;; 				    #f
;; 				    (cons sym output)))
;; 		       (append params demands)
;; 		       (vector->list (node-outputs region))))
;;   (define new-memory (car (drop (vector->list (node-outputs region)) (- (length params) 1) )))
;;   (define body-ctx (begin
;; 		     (node-output-type-set! new-memory 'memory)
;; 		     (make-compile-ctx new-memory)))
;;   (define body (compile-sexps (cddr s) body-ctx new-env))
;;   (region-add-result region body)
;;   (region-add-result region (compile-ctx-memory body-ctx))
;;   (vector-ref (node-outputs f) 0))

;; (define (compile-fix s ctx env)
;;   (define demands (demand-set (list s) (env-keys env)))
;;   (define captures (map (lambda (e) (env-lookup env e)) demands))
;;   (define params (map car (second s)))
;;   (define f (build-fix (map (lambda (n) (cons n 'scheme)) params) captures))
;;   (define region (body-region f))

;;   (define new-env (map (lambda (sym output) (cons sym output))
;; 		       (append params demands)
;; 		       (vector->list (node-outputs region))))

;;   (define lams (map (lambda (l)
;; 		      (compile-lambda (first l) (second l) ctx new-env))
;; 		    (second s)))
;;   (for lam lams
;;        (region-add-result region lam))
;;   ;; Push fixed to env temporarily
;;   (map (lambda (param output) (push! env (cons param output)))
;; 	 params
;; 	 (vector->list (node-outputs f)))
;;   (compile-sexps (cddr s) ctx env))

;; (define (compile-sexp s ctx env)
;;   (if (not (pair? s))
;;       (if (symbol? s)
;; 	  (compile-lookup s ctx env)
;; 	  (compile-self-evaluating s))
;;       (case (car s)
;; 	((fix) (compile-fix s ctx env))
;; 	((lambda) (compile-lambda "lambda" s ctx env))
;; 	((if) (compile-if s ctx env))
;; 	((define) (compile-define s ctx env))
;; 	((- < + =) (compile-builtin s ctx env))
;; 	(else
;; 	 (compile-call s ctx env)))))

;; (define (compile-sexps program ctx env)
;;   (if (null? (cdr program))
;;       (compile-sexp (car program) ctx env)
;;       (begin
;; 	(compile-sexp (car program) ctx env)
;; 	(compile-sexps (cdr program) ctx env))))

;; (define (compile-program s)
;;   (define fout (compile-lambda "repl" `(lambda () ,@s) (make-compile-ctx #f) '()))
;;   (node-output-node fout))

