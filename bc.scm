;; TODO: everything should really pass in the register to use
;; * control dst
;; * use 'any reg' for return, params, to prevent moves
;; * pretty much only call, local vars should cause moves
;; * check via lua
;;
;; * intern consts
;; * comments in output
;; * name more lambdas, define, let

;; * serializer, for both vm and bc

;; * lets shouldn't be modified by alexpander, but get let loop working
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

(define (compile-self-evaluating f bc rd tail)
  ;; TODO save len
  (define c (length (func-bc-consts bc)))
  (if (and  (number? f) (< (abs f) 30000))
      (push! (func-bc-code bc) (list 'KSHORT rd f))
      (begin
	(push! (func-bc-consts bc) f)
	(push! (func-bc-code bc) (list 'KONST rd c))))
  (finish bc tail rd))

(define (compile-binary f bc env rd tail)
  (define op (second (assq (first f) '((+ ADDVV) (- SUBVV) (< ISLT)))))
  (define r2 (+ rd 1))
  (compile-sexp (second f) bc env rd #f)
  (compile-sexp (third f) bc env r2 #f)
  (push! (func-bc-code bc) (list op rd rd r2))
  (finish bc tail rd))

(define (compile-if f bc env rd tail)
  (compile-sexp (second f) bc env rd #f)
  (define jop (list 'JMP 0))
  (define jop2 (list 'JMP 0))
  (when (= 3 (length f))
    (set! f (append f (list #f))))
  (push! (func-bc-code bc) (list 'ISF rd))
  (push! (func-bc-code bc) jop)
  (compile-sexp (third f) bc env rd tail)
  (if (not tail)
      (push! (func-bc-code bc) jop2)
      (finish bc tail rd))
  ;; TODO len
  (set! (second jop) (length (func-bc-code bc)))
  (compile-sexp (fourth f) bc env rd tail)
  (if (not tail)
      (begin
	(set! (second jop2) (length (func-bc-code bc)))
	(finish bc tail rd))
      #f))

(define (compile-lambda f bc rd tail)
  (define f-bc (make-func-bc (format "lambda~a" (next-id)) '() '() (length (second f))))
  (define f-id (length program))
  (push! program f-bc)
  (compile-lambda-internal f f-bc '())
  (push! (func-bc-code bc) (list 'KFUNC rd f-id))    
  (finish bc tail rd))

(define (compile-lambda-internal f f-bc env)
  (define r (length (second f)))
  (display (format "Lambda: ~a\n" f))
  (fold (lambda (n num)
	  (push! env (cons n num))
	  (+ num 1))
	0
	(second f))
  (compile-sexps (cddr f) f-bc env r #t)
  (finish f-bc #t r))

(define (compile-lookup f bc env rd tail)
  (define l (assq f env))
  ;;(display (format "Lookup ~a ~a\n" f env))
  (if l
      (when (not (= (cdr l) rd))
	(push! (func-bc-code bc) (list 'MOV (cdr l) rd)))
      (let* ((c (length (func-bc-consts bc))))
	(push! (func-bc-consts bc) f)
	(push! (func-bc-code bc) (list 'GGET rd c))
	(finish bc tail rd))))

(define (compile-call f bc env rd tail)
  (fold
   (lambda (f num)
     (compile-sexp f bc env num #f)
     (+ num 1))
   rd
   f)
  (push! (func-bc-code bc) (list (if tail 'CALLT 'CALL) rd (length f)))
  (if tail #f rd))

(define (compile-define f bc env rd tail)
  (if (pair? (second f))
      (compile-define
       `(define ,(car (second f)) (lambda ,(cdr (second f)) ,@(cddr f)))
       bc env rd tail)
      (let* ((g (length (func-bc-consts bc))))
	(compile-sexp (third f) bc env rd #f)
	(push! (func-bc-consts bc) (second f))
	(push! (func-bc-code bc) (list 'GSET g rd))
	;; TODO undef
	(finish bc tail rd))))

(define (compile-let f bc env rd tail)
  (define ord rd)
  (map (lambda (f)
	 (compile-sexp (second f) bc env ord #f)
	 (push! env (cons (first f) ord))
	 (inc! ord))
       (second f))
  (compile-sexps (cddr f) bc env ord tail)
  ;; TODO without mov?
  (push! (func-bc-code bc) (list 'MOV ord rd))
  (finish bc tail rd))

(define (compile-letrec f bc env rd tail)
  (define ord rd)
  (define mapping (map (lambda (f)
			 (define f-bc (make-func-bc (first f) '() '() (length (second (second f)))))
			 (define f-id (length program))
			 (define r ord)
			 (push! (func-bc-code bc) (list 'KFUNC ord f-id))
			 (inc! ord)
			 (push! program f-bc)
			 (list f-id f-bc r))
		       (second f)))
  (define new-env (map (lambda (a b)
			 (push! env (cons a b))
			 (cons a b))
	      (map first (second f))
	      (map third mapping)))
  (map (lambda (f mapping)
	 (compile-lambda-internal (second f) (second mapping) new-env))
       (second f)
       mapping)
  (compile-sexps (cddr f) bc env ord tail)
  (push! (func-bc-code bc) (list 'MOV ord rd))
  (finish bc tail rd))

(define (compile-sexp f bc env rd tail)
  (if (not (pair? f))
      (if (symbol? f)
	  (compile-lookup f bc env rd tail)
	  (compile-self-evaluating f bc rd tail))
      (case (car f)
	((define) (compile-define f bc env rd tail))
	((letrec) (compile-letrec f bc env rd tail))
	((let) (compile-let f bc env rd tail))
	((lambda) (compile-lambda f bc rd tail))
	((begin) (compile-sexps (cdr f) bc env rd tail))
	((if) (compile-if f bc env rd tail))
	((set!) (compile-set! f bc env rd tail))
	((quote) (compile-self-evaluating (second f) bc rd tail))
	((+ - <) (compile-binary f bc env rd tail))
	(else (compile-call f bc env rd tail)))))


(define (compile-sexps program bc env rd tail)
  (if (null? (cdr program)) 
    (compile-sexp (car program) bc env rd tail)
    (begin
      (compile-sexp (car program) bc env rd #f)
      (compile-sexps (cdr program) bc env rd tail))))

(define (compile d)
  (define bc (make-func-bc "repl" '() '() 0))
  (display (format "Compile: ~a \n" d))
  (compile-sexps d bc '() 0 #t)
  (push! program bc))

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

;;;;;;;;;;;;;print
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

;;;;;;;;;;;;;;;;;; main

(compile (expander))

(fold (lambda (a b)
	(display (format "~a -- " b))
	(display-bc a)
	(+ b 1))
      0
      (reverse program))

