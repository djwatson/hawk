;;;;;;;;;;;;;;chicken stuff
(import (r7rs))
(import (srfi 1)) ;; lists
(import (srfi 17)) ;; generalized-set!
(import (srfi 28)) ;; basic format
(import (srfi 99)) ;; define-record-type
(import (srfi 151)) ;; bitwise-ops
(import (chicken pretty-print))
(define-syntax define-getter-with-setter
  (syntax-rules ()
    ((_ getter setter)
     (set! getter (getter-with-setter getter setter)))))

;;;;;;;;;;;;; include

(include "third-party/alexpander.scm")
(include "memory_layout.scm")
(include "passes.scm")

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
      (if (equal? (car l) c)
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
    (if (and  (fixnum? f) (< (abs f) 65535))
	(push! (func-bc-code bc) (list 'KSHORT rd f))
	(let ((c (get-or-push-const bc f)))
	  (push! (func-bc-code bc) (list 'KONST rd c))))))

(define (compile-binary f bc env rd cd)
  (define vn '($- $+ $guard $closure-get))
  (if (and (memq (first f) vn)
	   (fixnum? (third f))
	   (< (abs (third f)) 65535))
      (compile-binary-vn f bc env rd cd)
      (compile-binary-vv f bc env rd cd)))

(define (compile-binary-vv f bc env rd cd)
  (define op (second (if (branch-dest? cd)
			 (assq (first f)
			       '(($< JISLT) ($= JISEQ)))
			 (assq (first f)
			       '(($+ ADDVV) ($- SUBVV) ($< ISLT)
				 ($* MULVV)
				 ($= ISEQ) ($eq EQ)
				 ($set-box! SET-BOX!)
				 ($cons CONS)
				 ($make-vector MAKE-VECTOR)
				 ($vector-ref VECTOR-REF)
				 ($make-string MAKE-STRING)
				 ($string-ref STRING-REF)
				 ($apply APPLY))))))
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
			   '(($+ ADDVN) ($- SUBVN)
			     ($guard GUARD) ($closure CLOSURE) ($closure-get CLOSURE-GET)))))
  (define r1 (exp-loc (second f) env rd))
  (when cd
    (finish bc cd rd)
    (push! (func-bc-code bc) (list op rd r1 (third f)))
    (compile-sexp (second f) bc env r1 'next)))

(define (compile-unary f bc env rd cd)
  (define op (second (assq (first f)
			   '(($box BOX) ($unbox UNBOX)
			     ($car CAR) ($cdr CDR)
			     ($vector-length VECTOR-LENGTH)
			     ($string-length STRING-LENGTH)
			     ($display DISPLAY)))))
  (define r1 (exp-loc (second f) env rd))
  (when cd
    (finish bc cd rd)
    (push! (func-bc-code bc) (list op rd r1))
    (compile-sexp (second f) bc env r1 'next)))

(define (compile-if f bc env rd cd)
  ;;(display (format "Compile-if ~a RD:~a CD:~a\n" f rd cd))
  (define dest (cond
		((eq? cd 'ret) cd)
		((branch-dest? cd)
		 (push! (func-bc-code bc) (list 'JMP (third cd)))
		 (push! (func-bc-code bc) (list 'ISF rd))
		 (length (func-bc-code bc)))
		((number? cd) cd)
		((eq? cd 'next)
		 (length (func-bc-code bc)))))
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

(define (ilength l)
  (if (null? l) 0
      (if (atom? l) 1
	  (+ 1 (ilength (cdr l))))))

(define (compile-lambda-internal f f-bc env)
  (define r (ilength (second f)))
  (define rest (improper? (second f)))
  ;;(display (format "Lambda: ~a\n" f))
  (fold (lambda (n num)
	  (push! env (cons n num))
	  (+ num 1))
	0
	(to-proper (second f)))
  (compile-sexps (cddr f) f-bc env r 'ret)
  (push! (func-bc-code f-bc)
	 (if rest (list 'FUNC (- r 1) 1)
	     (list 'FUNC r 0))))

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

;; Note we implicitly add the closure param here.
;; TODO optimize better for known calls.
(define (compile-call f bc env rd cd)
  (finish bc cd rd)
  (push! (func-bc-code bc) (list (if (eq? cd 'ret) 'CALLT 'CALL) rd (+ 1 (length f))))
  (push! (func-bc-code bc) (list 'CLOSURE-PTR rd (+ rd 1)))
  (fold
   (lambda (f num)
     (compile-sexp f bc env num 'next)
     (- num 1))
   (+ (length f) rd)
   (reverse f)))

(define (compile-closure f bc env rd cd)
  (finish bc cd rd)
  (push! (func-bc-code bc) (list 'CLOSURE rd (- (length f) 1)))
  (fold
   (lambda (f num)
     (compile-sexp f bc env num 'next)
     (- num 1))
   (+ (length f) rd -2)
   (reverse (cdr f))))

;; Third arg must be immediate fixnum.
(define (compile-closure-set f bc env rd cd)
  (finish bc cd rd)
  (define r1 (exp-loc (second f) env rd))
  (define r2 (exp-loc (third f) env (max rd (+ r1 1))))
  (push! (func-bc-code bc) (list 'CLOSURE-SET r1 r2 (fourth f)))
  (compile-sexp (third f) bc env r2 'next)
  (compile-sexp (second f) bc env r1 'next))

;; First arg is register to use, k, then obj
(define (compile-setter f bc env rd cd)
  (finish bc cd rd)
  (define r1 (exp-loc (second f) env rd))
  (define r2 (exp-loc (third f) env (max rd (+ r1 1))))
  (define r3 (exp-loc (fourth f) env (max rd (+ r2 1))))
  (push! (func-bc-code bc) (list (if (eq? '$vector-set! (first f)) 'VECTOR-SET 'STRING-SET) r1 r2 r3))
  (compile-sexp (fourth f) bc env r3 'next)
  (compile-sexp (third f) bc env r2 'next)
  (compile-sexp (second f) bc env r1 'next))

(define (compile-setter2 f bc env rd cd)
  (finish bc cd rd)
  (define r1 (exp-loc (second f) env rd))
  (define r2 (exp-loc (third f) env (max rd (+ r1 1))))
  (push! (func-bc-code bc) (list (if (eq? '$set-car! (first f)) 'SET-CAR 'SET-CDR) r1 r2))
  (compile-sexp (third f) bc env r2 'next)
  (compile-sexp (second f) bc env r1 'next))

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
  (define orig-env env) ;; let values use original mapping
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
  ;; Do this in reverse, so that we don't smash register usage.
  (for-each (lambda (f r)
	 (compile-sexp (second f) bc orig-env r 'next))
	    (reverse (second f))
	    (reverse mapping)))

(define (compile-sexp f bc env rd cd)
  ;;(display (format "SEXP: ~a env ~a\n" f env))
  (if (not (pair? f))
      (if (symbol? f)
	  (compile-lookup f bc env rd cd)
	  (compile-self-evaluating f bc rd cd))
      (case (car f)
	;; The standard scheme forms.
	((define) (compile-define f bc env rd cd))
	((let) (compile-let f bc env rd cd))
	((lambda) (compile-lambda f bc rd cd))
	((begin) (compile-sexps (cdr f) bc env rd cd))
	((if) (compile-if f bc env rd cd))
	((set!) (compile-define f bc env rd cd)) ;; TODO check?
	((quote) (compile-self-evaluating (second f) bc rd cd))

	;; Builtins
	(($+ $* $- $< $= $guard $set-box! $closure-get $eq $cons
	     $make-vector $vector-ref $make-string $string-ref $apply)
	 (compile-binary f bc env rd cd))
	(($vector-set! $string-set!) (compile-setter f bc env rd cd))
	(($set-car! $set-cdr!) (compile-setter2 f bc env rd cd))
	(($box $unbox $car $cdr $vector-length $display $string-length) (compile-unary f bc env rd cd))
	(($closure) (compile-closure f bc env rd cd))
	(($closure-set) (compile-closure-set f bc env rd cd))
	(else
	 (compile-call f bc env rd cd)))))

(define (compile-sexps program bc env rd cd)
  (let loop ((program (reverse program)) (cd cd))
    (compile-sexp (car program) bc env rd cd)
    (if (pair? (cdr program))
	(loop (cdr program) 'next))))

(define (compile d)
  (define bc (make-func-bc "repl" '()))
  (push! program bc)
  (display "Compile:\n")
  (pretty-print d)
  (newline)
  (compile-sexps d bc '() 0 'ret)
  (push! (func-bc-code bc) (list 'FUNC 0 0)))

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
	       (JISLT 22)
	       (JFUNC 23)
	       (JLOOP 24)
	       (GUARD 25)
	       (MULVV 26)
	       (BOX 27)
	       (UNBOX 28)
	       (SET-BOX! 29)
	       (CLOSURE 30)
	       (CLOSURE-GET 31)
	       (CLOSURE-PTR 32)
	       (CLOSURE-SET 33)
	       (EQ 34)
	       (CONS 35)
	       (CAR 36)
	       (CDR 37)
	       (MAKE-VECTOR 38)
	       (VECTOR-SET 39)
	       (VECTOR-REF 40)
	       (VECTOR-LENGTH 41)
	       (SET-CAR 42)
	       (SET-CDR 43)
	       (DISPLAY 44)
	       (STRING-LENGTH 45)
	       (STRING-REF 46)
	       (STRING-SET 47)
	       (MAKE-STRING 48)
	       (APPLY 49)))

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

(import (chicken foreign))

;; (define write-double
;;   (foreign-lambda* long ((double x))
;; 		   "long ret;"
;; 		   "memcpy(&ret, &x, 8);"
;; 		   "C_return(ret);"))

(define symbol-table '())
(define (bc-write-const c p)
  (cond
   ((symbol? c)
    (let ((pos (find-const symbol-table (- (length symbol-table) 1) c)))
      (if pos
	  (write-u64 (bitwise-ior symbol-tag (arithmetic-shift pos 3)) p)
	  (let* ((pos (length symbol-table))
		(str (symbol->string c))
		(len (string-length str)))
	    (push! symbol-table c)
	    (write-u64 (bitwise-ior symbol-tag (arithmetic-shift pos 3)) p)
	    (write-u64 len p)
	    (display str p)))))
   ((flonum? c)
    (write-u64 flonum-tag p)
    (write-u64 (write-double c) p))
   ((and  (fixnum? c) (< c #x8000000000000000) (> c (- #x8000000000000000)))
    (write-u64 (* 8 c) p))
   ((char? c)
    (write-u64 (bitwise-ior char-tag (arithmetic-shift (char->integer c) 8)) p))
   ((boolean? c)
    (write-u64 (if c true-rep false-rep) p))
   ((null? c)
    (write-u64 nil-tag p))
   ((string? c)
    (write-u64 ptr-tag p)
    (write-u64 string-tag p)
    (write-u64 (string-length c) p)
    (for-each (lambda (c) (write-u8 (char->integer c) p)) (string->list c)))
   ((vector? c)
    (write-u64 ptr-tag p)
    (write-u64 vector-tag p)
    (write-u64 (vector-length c) p)
    (do ((i 0 (+ i 1)))
	((= i (vector-length c)))
      (bc-write-const (vector-ref c i) p)))
   ((pair? c)
    (write-u64 cons-tag p)
    (bc-write-const (car c) p)
    (bc-write-const (cdr c) p))
   (else (display (format "Can't serialize: ~a\n" c)) (exit -1))))

(define (bc-write name program)
  (define p (open-output-file name))
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
     (bc-write-const c p))
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
  (close-output-port p))

;;;;;;;;;;;;;;;;;; main

(compile (closure-conversion
	  (optimize-direct
	   (assignment-conversion
	    (fix-letrec
	     (expander))))))
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

