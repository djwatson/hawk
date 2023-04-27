;; TODO: everything should really pass in the register to use
;; * Destination driven code gen
;; * fix reg usage
;; * fix reg in call
;; * tailcall
;; * comments in output
;; * name more lambdas, define, let

;; * rest params
;; * fix letrec
;; * assignment conversion
;; * closure conversion

;;;;;;;;;;;;;;chicken stuff
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

;;;;;;;;;;;;; include

(include "third-party/alexpander.scm")

;;;;;;;;;;;;;;;;; util
(define-syntax inc!
  (syntax-rules ()
    ((_ var) (set! var (+ 1 var)))))

(define-syntax push!
  (syntax-rules ()
    ((_ var val) (set! var (cons val var)))))

(define next-id
  (let ((cur-node 0))
    (lambda ()
      (inc! cur-node)
      cur-node)))
;;;;;;;;;;;;;;;;;;; code

(define program '())

;; TODO reg = free reg set
(define-record-type func-bc #t #t
		    (name) (code) (consts) (reg))
 (define-getter-with-setter func-bc-code func-bc-code-set!)
 (define-getter-with-setter func-bc-consts func-bc-consts-set!)
 (define-getter-with-setter func-bc-reg func-bc-reg-set!)

(define (finish bc tail r)
  ;; TODO reg
  (if (and r tail)
      (begin (push! (func-bc-code bc) (list 'RET1 r))
	     #f)
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
  (define op (second (assq (first f) '((+ ADDVV) (- SUBVV) (< ISLT)))))
  (inc! (func-bc-reg bc))
  (push! (func-bc-code bc) (list op r r1 r2))
  (finish bc tail r))

(define (compile-if f bc env tail)
  (define r (compile-sexp (second f) bc env #f))
  (define jop (list 'JMP 0))
  (define jop2 (list 'JMP 0))
  (when (= 3 (length f))
    (set! f (append f (list #f))))
  (push! (func-bc-code bc) (list 'ISF r))
  (push! (func-bc-code bc) jop)
  (let ((rt (compile-sexp (third f) bc env tail)))
    (if (not tail)
	(push! (func-bc-code bc) jop2)
	(finish bc tail rt))
    ;; TODO len
    (set! (second jop) (length (func-bc-code bc)))
    (let ((rf (compile-sexp (fourth f) bc env tail)))
      (if (not tail)
	  (begin
	    (when (not (eqv? rf rt))
	      (push! (func-bc-code bc) `(MOV ,rf ,rt)))
	    (set! (second jop2) (length (func-bc-code bc)))
	    (finish bc tail rf))
	  #f))))

(define (compile-lambda f bc tail)
  (define f-bc (make-func-bc (format "lambda~a" (next-id)) '() '() (length (second f))))
  (define f-id (length program))
  (push! program f-bc)
  (define r (func-bc-reg bc))
  (inc! (func-bc-reg bc))
  (compile-lambda-internal f f-bc '())
  (push! (func-bc-code bc) (list 'KFUNC r f-id))    
  (finish bc tail r))

(define (compile-lambda-internal f f-bc env)
  (display (format "Lambda: ~a\n" f))
  (fold (lambda (n num)
	  (push! env (cons n num))
	  (+ num 1))
	0
	(second f))
  (finish f-bc #t (compile-sexps (cddr f) f-bc env #t)))

(define (compile-lookup f bc env tail)
  (define l (assq f env))
  ;;(display (format "Lookup ~a ~a\n" f env))
  (if l
      (if (number? (cdr l))
	  (cdr l)
	  (let ((r (func-bc-reg bc)))
	    (inc! (func-bc-reg bc))
	    (push! (func-bc-code bc) (list 'KFUNC r (second (cdr l))))
	    r))
      (let* ((r (func-bc-reg bc))
	     (c (length (func-bc-consts bc))))
	(inc! (func-bc-reg bc))
	(push! (func-bc-consts bc) f)
	(push! (func-bc-code bc) (list 'GGET r c))
	(finish bc tail r))))

(define (compile-call f bc env tail)
  (define r (func-bc-reg bc))
  ;; start reg
  ;; TODO mov to correct reg place
  (for-each
   (lambda (f) (compile-sexp f bc env #f))
   f)
  (push! (func-bc-code bc) (list (if tail 'CALLT 'CALL) r (length f)))
  (if tail #f r))

(define (compile-define f bc env tail)
  (if (pair? (second f))
      (compile-define
       `(define ,(car (second f)) (lambda ,(cdr (second f)) ,@(cddr f)))
       bc env tail)
      (let* ((r (compile-sexp (third f) bc env #f))
	     (g (length (func-bc-consts bc))))
	(push! (func-bc-consts bc) (second f))
	(push! (func-bc-code bc) (list 'GSET g r))
	;; TODO undef
	(finish bc tail r))))

(define (compile-let f bc env tail)
  (define rs (map (lambda (f) (compile-sexp (second f) bc env #f))
		  (second f)))
  (for-each (lambda (name r) (push! env (cons name r)))
	    (map first (second f))
	    rs)
  (finish bc tail (compile-sexps (cddr f) bc env tail)))

(define (compile-letrec f bc env tail)
  (define mapping (map (lambda (f)
			 (define f-bc (make-func-bc (first f) '() '() (length (second (second f)))))
			 (define f-id (length program))
			 (inc! (func-bc-reg bc))
			 (push! program f-bc)
			 (list f-id f-bc))
		       (second f)))
  (define new-env (map (lambda (name r)
		(cons name (list 'KFUNC r)))
	      (map first (second f))
	      (map first mapping)))
  (map (lambda (f mapping)
	 (compile-lambda-internal (second f) (second mapping) new-env))
       (second f)
       mapping)
  (finish bc tail (compile-sexps (cddr f) bc env tail)))

(define (compile-sexp f bc env tail)
  (if (not (pair? f))
      (if (symbol? f)
	  (compile-lookup f bc env tail)
	  (compile-self-evaluating f bc tail))
      (case (car f)
	((define) (compile-define f bc env tail))
	((letrec) (compile-letrec f bc env tail))
	((let) (compile-let f bc env tail))
	((lambda) (compile-lambda f bc tail))
	((begin) (compile-sexps (cdr f) bc env tail))
	((if) (compile-if f bc env tail))
	((set!) (compile-set! f bc env tail))
	((quote) (compile-self-evaluating (second f) bc tail))
	((+ - <) (compile-binary f bc env tail))
	(else (compile-call f bc env tail)))))


(define (compile-sexps program bc env tail)
  (if (null? (cdr program)) 
    (compile-sexp (car program) bc env tail)
    (begin
      (compile-sexp (car program) bc env #f)
      (compile-sexps (cdr program) bc env tail))))

(define (compile d)
  (define bc (make-func-bc "repl" '() '() 0))
  (display (format "Compile: ~a \n" d))
  (compile-sexps d bc '() #t)
  (push! program bc))

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
	0 (reverse (func-bc-code bc)))
  (newline))

;;;;;;;;;;;;;expander
(define (read-file)
  (define (read-file-rec sexps)
    (define next (read))
    (if (eof-object? next) 
      (reverse sexps)
      (read-file-rec (cons next sexps))))

  (read-file-rec '()))

(define store (null-mstore))
(define (expander )
  (expand-top-level-forms! (read-file) store))

(compile (expander))

;;;;;;;;;;;;;print
(fold (lambda (a b)
	(display (format "~a -- " b))
	(display-bc a)
	(+ b 1))
      0
      (reverse program))

