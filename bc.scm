;;;;;;;;;;;;;;chicken stuff
(import (r7rs))
(import (srfi 1)) ;; lists
(import (srfi 17)) ;; generalized-set!
(import (srfi 28)) ;; basic format
(import (srfi 99)) ;; define-record-type
(import (srfi 151)) ;; bitwise-ops
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
(define consts '())

;; TODO reg = free reg set
(define-record-type func-bc #t #t
		    (name) (code))
(define-getter-with-setter func-bc-code func-bc-code-set!)

(define (find-const l i c)
  (if (pair? l)
      (if (eq? (car l) c)
	  i
	  (find-const (cdr l) (- i 1) c))
      #f))

(define (get-or-push-const bc c)
  (define f (find-const consts (- (length consts) 1) c))
  (if f
      f
      (let ((i (length consts)))
	(push! consts c)
	(when (> i 65535)
	  (display "Error: Const pool overflow")
	  (exit -1))
	i)))

(define (branch-dest? cd)
  (and (pair? cd) (eq? 'if (first cd))))

(define (finish bc cd r)
  (cond
   ((eq? cd 'ret)
    (push! (func-bc-code bc) (list 'RET1 r)))
   ((number? cd)
    (let ((jlen (- (length (func-bc-code bc)) cd -1)))
	    (when (not (eq? jlen 1))
	      (push! (func-bc-code bc) (list 'JMP jlen)))))
   ((branch-dest? cd)
      (push! (func-bc-code bc) (list 'JMP (third cd)))
      (push! (func-bc-code bc) (list 'ISF r)))
   ((eq? cd 'next))
   (else (display (format "UNKNOWN CONTROL DEST:~a" cd)) (exit -1))))

(define (compile-self-evaluating f bc rd cd)
  ;; TODO save len
  (when cd
    (finish bc cd rd)
    (if (and  (number? f) (< (abs f) 65535))
	(push! (func-bc-code bc) (list 'KSHORT rd f))
	(let ((c (get-or-push-const bc f)))
	  (push! (func-bc-code bc) (list 'KONST rd c))))))

(define (compile-binary f bc env rd cd)
  (define vn '(- +))
  (if (and (memq (first f) vn)
	   (number? (third f))
	   (< (abs (third f)) 65535))
      (compile-binary-vn f bc env rd cd)
      (compile-binary-vv f bc env rd cd)))

(define (compile-binary-vv f bc env rd cd)
  (define op (second (if (branch-dest? cd)
			 (assq (first f)
			       '((< JISLT) (= JISEQ)))
			 (assq (first f)
			       '((+ ADDVV) (- SUBVV) (< ISLT)
				 (= ISEQ))))))
  (define r1 (exp-loc (second f) env rd))
  (define r2 (exp-loc (third f) env (max rd (+ r1 1))))
  (when cd
    (if (branch-dest? cd)
	(push! (func-bc-code bc) (list 'JMP (third cd)))
	(finish bc cd rd))
    (push! (func-bc-code bc) (list op rd r1 r2))
    (compile-sexp (third f) bc env r2 'next)
    (compile-sexp (second f) bc env r1 'next)))

(define (compile-binary-vn f bc env rd cd)
  (define op (second (assq (first f)
			   '((+ ADDVN) (- SUBVN)))))
  (define r1 (exp-loc (second f) env rd))
  (when cd
    (finish bc cd rd)
    (push! (func-bc-code bc) (list op rd r1 (third f)))
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
      (compile-sexp (second f) bc env r1 `(if ,(length (func-bc-code bc)) ,(- (length (func-bc-code bc)) pos -1))))))

(define (compile-lambda f bc rd cd)
  (define f-bc (make-func-bc (format "lambda~a" (next-id)) '() ))
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
  (compile-sexps (cddr f) f-bc env r 'ret)
  (push! (func-bc-code f-bc) (list 'FUNC r)))

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
      (let* ((c (get-or-push-const bc f)))
	(push! (func-bc-code bc) (list 'GGET r c)))))

(define (compile-call f bc env rd cd)
  (push! (func-bc-code bc) (list (if (eq? cd 'ret) 'CALLT 'CALL) rd (length f)))
  (fold
   (lambda (f num)
     (compile-sexp f bc env num 'next)
     (- num 1))
   (+ (length f) -1 rd)
   (reverse f)))

(define (compile-define f bc env rd cd)
  (if (pair? (second f))
      (compile-define
       `(define ,(car (second f)) (lambda ,(cdr (second f)) ,@(cddr f)))
       bc env rd cd)
      (let* ((c (get-or-push-const bc (second f))))
	;; TODO undef
	(finish bc cd rd)
	(push! (func-bc-code bc) (list 'GSET c rd))
	(compile-sexp (third f) bc env rd 'next)
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
			 (define f-bc (make-func-bc (first f) '()))
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
	(loop (cdr program) 'next))))

(define (compile d)
  (define bc (make-func-bc "repl" '()))
  (push! program bc)
  (display (format "Compile: ~a \n" d))
  (compile-sexps d bc '() 0 'ret)
  (push! (func-bc-code bc) (list 'FUNC 0)))

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
  (display "Code:\n")
  (fold (lambda (a b)
	  (display (format "~a: ~a\n" b a))
	  (+ b 1))
	0 (func-bc-code bc))
  (newline))

;;;;;;;;;;;;;; serialize bc

(define enum '(
	       (FUNC 0)
	       (KSHORT 1)
	       (ISGE 2)
	       (JMP 3)
	       (RET1 4)
	       (SUBVN 5)
	       (CALL 6)
	       (ADDVV 7)
	       (HALT 8)
	       (ALLOC 9)
	       (ISLT 10)
	       (ISF 11)
	       (SUBVV 12)
	       (GGET 13)
	       (GSET 14)
	       (KFUNC 15)
	       (CALLT 16)
	       (KONST 17)
	       (MOV 18)
	       (ISEQ 19)
	       (ADDVN 20)
	       (JISEQ 21)
	       (JISLT 22)))

(define bc-ins '(KSHORT))

(define (write-uint v p)
  (write-u8 (bitwise-and v #xff) p)
  (write-u8 (bitwise-and (arithmetic-shift v -8) #xff) p)
  (write-u8 (bitwise-and (arithmetic-shift v -16) #xff) p)
  (write-u8 (bitwise-and (arithmetic-shift v -24) #xff) p))

(define (write-u64 v p)
  (write-u8 (bitwise-and v #xff) p)
  (write-u8 (bitwise-and (arithmetic-shift v -8) #xff) p)
  (write-u8 (bitwise-and (arithmetic-shift v -16) #xff) p)
  (write-u8 (bitwise-and (arithmetic-shift v -24) #xff) p)
  (write-u8 (bitwise-and (arithmetic-shift v -32) #xff) p)
  (write-u8 (bitwise-and (arithmetic-shift v -40) #xff) p)
  (write-u8 (bitwise-and (arithmetic-shift v -48) #xff) p)
  (write-u8 (bitwise-and (arithmetic-shift v -56) #xff) p))

(define (write-u16 v p)
  (write-u8 (remainder v 256) p)
  (write-u8 (remainder (quotient v 256) 256) p))

(define (bc-write name program)
  (define p (open-output-file name))
  (define globals '())
  ;; Magic
  (write-u8 (char->integer #\B) p)
  (write-u8 (char->integer #\O) p)
  (write-u8 (char->integer #\O) p)
  (write-u8 (char->integer #\M) p)
  ;; version
  (write-uint 0 p)
  ;; number of consts in const pool
  (write-uint (length consts) p)
  (for-each
   (lambda (c)
     (cond
      ((symbol? c)
       (let ((pos (length globals)))
	 (push! globals c)
	 (write-u64 (+ (* pos 8) 4) p)))
      ((integer? c)
       (write-u64 (* 8 c) p))
      (else (display (format "Can't serialize: ~a\n" c)) (exit -1))))
   consts)  
  ;; number of bc
  (write-uint (length program) p)
  (for-each
   (lambda (bc)

     (write-uint (length (func-bc-code bc)) p)
     (for-each
      (lambda (c)
	(define ins (assq (first c) enum))
	(when (not ins)
	  (display (format "ERROR could not find ins ~a\n" c))
	  (exit -1))
	(write-u8 (second ins) p)
	(write-u8 (if (> (length c) 1) (second c) 0) p)
	(if (memq (first c) bc-ins)
	    (write-u16 (third c) p)
	    (begin
	      (write-u8 (if (> (length c) 2) (third c) 0) p)
	      (write-u8 (if (> (length c) 3) (fourth c) 0) p))))
      (func-bc-code bc)))
   program)
  (write-uint (length globals) p)
  (for-each
   (lambda (c)
     (define s (symbol->string c))
     (write-uint (string-length s) p)
     (display (symbol->string c) p))
   (reverse! globals))
  (close-output-port p))

;;;;;;;;;;;;;;;;;; main

(compile (expander))
;; Get everything in correct order
;; TODO do this as we are generating with extendable vectors
(set! consts (reverse! consts))
(set! program (reverse! program))

(display "Consts:\n")
(fold (lambda (a b)
	(display (format "~a: ~a\n" b a))
	(+ b 1))
      0 consts)
(newline)
(fold (lambda (a b)
	(display (format "~a -- " b))
	(display-bc a)
	(+ b 1))
      0
      program)

(bc-write "out.bc" program)

