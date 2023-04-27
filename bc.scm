;; TODO: everything should really pass in the register to use
;; * control dst
;; * use 'any reg' for return, params, to prevent moves
;; * pretty much only call, local vars should cause moves
;; * check via lua
;;
;; * tail call register alloc?
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

(define (finish bc cd r)
  ;; TODO reg
  (if (eq? cd 'ret)
      (push! (func-bc-code bc) (list 'RET1 r))
      (if (number? cd)
	  (let ((jlen (- (length (func-bc-code bc)) cd -1)))
	    (when (not (eq? jlen 1))
	      (push! (func-bc-code bc) (list 'JMP jlen)))))))

(define (compile-self-evaluating f bc rd cd)
  ;; TODO save len
  (define c (length (func-bc-consts bc)))
  (when cd
    (finish bc cd rd)
    (if (and  (number? f) (< (abs f) 30000))
	(push! (func-bc-code bc) (list 'KSHORT rd f))
	(begin
	  (push! (func-bc-consts bc) f)
	  (push! (func-bc-code bc) (list 'KONST rd c))))))

(define (compile-binary f bc env rd cd)
  (define op (second (assq (first f)
			   '((+ ADDVV) (- SUBVV) (< ISLT)
			     (= ISEQ)))))
  (define r1 (exp-loc (second f) env rd))
  (define r2 (exp-loc (third f) env (max rd (+ r1 1))))
  (when cd
    (finish bc cd rd)
    (push! (func-bc-code bc) (list op rd r1 r2))
    (compile-sexp (third f) bc env r2 'next)
    (compile-sexp (second f) bc env r1 'next)))

(define (compile-if f bc env rd cd)
  (define dest (if (eq? cd 'ret) 'ret (length (func-bc-code bc))))
  (define r1 (exp-loc (second f) env rd))
  (when (= 3 (length f))
    (set! f (append f (list #f))))
  (when cd
    (compile-sexp (fourth f) bc env rd dest)
    (let ((pos (length (func-bc-code bc))))
      (compile-sexp (third f) bc env rd dest)
      (push! (func-bc-code bc) (list 'JMP (- (length (func-bc-code bc))  pos -1)))
      (push! (func-bc-code bc) (list 'ISF r1))
      (compile-sexp (second f) bc env r1 'if))))

(define (compile-lambda f bc rd cd)
  (define f-bc (make-func-bc (format "lambda~a" (next-id)) '() '() (length (second f))))
  (define f-id (length program))
  (push! program f-bc)
  (compile-lambda-internal f f-bc '())
  (finish bc cd rd)
  (push! (func-bc-code bc) (list 'KFUNC rd f-id)))

(define (compile-lambda-internal f f-bc env)
  (define r (length (second f)))
  (display (format "Lambda: ~a\n" f))
  (fold (lambda (n num)
	  (push! env (cons n num))
	  (+ num 1))
	0
	(second f))
  (compile-sexps (cddr f) f-bc env r 'ret))

(define (exp-loc f env rd)
  (if (symbol? f)
      (or (find-symbol f env) rd)
      rd))

(define (find-symbol f env)
  (define l (assq f env))
  (if l (cdr l) #f))

(define (compile-lookup f bc env rd cd)
  (define loc (find-symbol f env))
  ;;(display (format "Lookup ~a ~a\n" f env))
  (define r (if (eq? cd 'ret) (exp-loc f env rd) rd))
  (finish bc cd r)
  (if loc
      (when (not (= loc r))
	(push! (func-bc-code bc) (list 'MOV loc r)))
      (let* ((c (length (func-bc-consts bc))))
	(push! (func-bc-consts bc) f)
	(push! (func-bc-code bc) (list 'GGET r c)))))

(define (compile-call f bc env rd cd)
  (push! (func-bc-code bc) (list (if (eq? cd 'ret) 'CALLT 'CALL) rd (length f)))
  (fold
   (lambda (f num)
     (compile-sexp f bc env num 'next)
     (+ num 1))
   rd f))

(define (compile-define f bc env rd cd)
  (if (pair? (second f))
      (compile-define
       `(define ,(car (second f)) (lambda ,(cdr (second f)) ,@(cddr f)))
       bc env rd cd)
      (let* ((g (length (func-bc-consts bc))))
	;; TODO undef
	(finish bc cd rd)
	(push! (func-bc-consts bc) (second f))
	(push! (func-bc-code bc) (list 'GSET g rd))
	(compile-sexp (third f) bc env rd #f)
	)))

(define (compile-let f bc env rd cd)
  (define ord rd)
  (define mapping (map (lambda (f)
			 (define o ord)
			 (push! env (cons (first f) ord))
			 (inc! ord)
			 o)
		       (second f)))
  ;; TODO without mov?
  (when (and cd (not (eq? cd 'ret)))
    (push! (func-bc-code bc) (list 'MOV ord rd)))
  (compile-sexps (cddr f) bc env ord cd)
  (map (lambda (f r)
	 (compile-sexp (second f) bc env r 'next))
       (second f)
       mapping))

;; TODO needs closure conversion
(define (compile-letrec f bc env rd cd)
  (define ord rd)
  (define mapping (map (lambda (f)
			 (define f-bc (make-func-bc (first f) '() '() (length (second (second f)))))
			 (define f-id (length program))
			 (define r ord)
			 (inc! ord)
			 (push! program f-bc)
			 (list f-id f-bc r))
		       (second f)))
  (define new-env (map (lambda (a b)
			 (push! env (cons a b))
			 (cons a b))
	      (map first (second f))
	      (map third mapping)))
  (when (and cd (not (eq? cd 'ret)))
    (push! (func-bc-code bc) (list 'MOV ord rd)))
  (compile-sexps (cddr f) bc env ord cd)
  (map (lambda (f)
	 (push! (func-bc-code bc) (list 'KFUNC (third f) (first f))))
       mapping)
  (map (lambda (f mapping)
	 (compile-lambda-internal (second f) (second mapping) new-env))
       (second f)
       mapping))

(define (compile-sexp f bc env rd cd)
  (if (not (pair? f))
      (if (symbol? f)
	  (compile-lookup f bc env rd cd)
	  (compile-self-evaluating f bc rd cd))
      (case (car f)
	((define) (compile-define f bc env rd cd))
	((letrec) (compile-letrec f bc env rd cd))
	((let) (compile-let f bc env rd cd))
	((lambda) (compile-lambda f bc rd cd))
	((begin) (compile-sexps (cdr f) bc env rd cd))
	((if) (compile-if f bc env rd cd))
	((set!) (compile-set! f bc env rd cd))
	((quote) (compile-self-evaluating (second f) bc rd cd))
	((+ - < =) (compile-binary f bc env rd cd))
	(else (compile-call f bc env rd cd)))))


(define (compile-sexps program bc env rd cd)
  (let loop ((program (reverse program)) (cd cd))
    (compile-sexp (car program) bc env rd cd)
    (if (pair? (cdr program))
	(loop (cdr program) #f))))

(define (compile d)
  (define bc (make-func-bc "repl" '() '() 0))
  (display (format "Compile: ~a \n" d))
  (compile-sexps d bc '() 0 'ret)
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
	0 (func-bc-code bc))
  (newline))

;;;;;;;;;;;;;;;;;; main

(compile (expander))

(fold (lambda (a b)
	(display (format "~a -- " b))
	(display-bc a)
	(+ b 1))
      0
      (reverse program))

