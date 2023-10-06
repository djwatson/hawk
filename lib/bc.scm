;;;;;;;;;; Currently a limitation in macro expander:
;;;;;;;;;;; whole file is read before includes processed, so macros used in file can't be included
(define-syntax inc!
  (syntax-rules ()
    ((_ var) (set! var (+ 1 var)))))

(define-syntax push!
  (syntax-rules ()
    ((_ var val) (set! var (cons val var)))))
(define-syntax when
  (syntax-rules ()
    ((_ cond body ...)
     (if cond (begin body ...)))))

(define-syntax ->
  (syntax-rules ()
    ((_ arg (command args ...) rest ...)
     (->
      (command arg args ...) rest ...))
    ((_ arg command rest ...)
     (-> (command arg) rest ...))
    ((_ arg) arg)))

(include "util.scm")

;;;;;;;;;;;;; include

(include "third-party/alexpander.scm")
(include "memory_layout.scm")
(include "passes.scm")

;;;;;;;;;;;;;;;;;;; code

(define program '())
(define consts '())

;; TODO reg = free reg set
;; (define-record-type func-bc #t #t
;; 		    (name) (code))
(define (make-func-bc name code)
  (vector name code))
(define (func-bc-code-set! bc code)
  (vector-set! bc 1 code))
(define (func-bc-code bc)
  (vector-ref bc 1))
(define (func-bc-name bc)
  (vector-ref bc 0))

(define (push-instr! bc c)
  (func-bc-code-set! bc (cons c (func-bc-code bc))))

(define const-length 0)
(define (find-const l i c)
  (let loop ((l l) (i i) (c c))
    (if (pair? l)
	(if (equal? (car l) c)
	    i
	    (loop (cdr l) (- i 1) c))
	#f)))

(define (get-or-push-const bc c)
  (define f (find-const consts (- const-length 1) c))
  (if f
      f
      (let ((i const-length))
	(push! consts c)
	(set! const-length (+ 1 const-length))
	(when (> i 65535)
	  (display "Error: Const pool overflow")
	  (exit -1))
	i)))

(define (branch-dest? cd)
  (and (pair? cd) (eq? 'if (first cd))))

;; can-omit: jumps immediately following a branch statement
;; *cannot* be omitted, since they are rolled in to the previous
;; op's handling in the vm.
(define (build-jmp absolute bc can-omit)
  ;;(dformat "BUild jmp to abs ~a can omit ~a len ~a\n" absolute can-omit (length (func-bc-code bc)))
  (let ((offset (- (length (func-bc-code bc)) absolute -1)))
    (when (or (<= offset 0) (> offset 65535))
      (dformat "OFFSET too big: ~a\n" offset)
      (exit -1))    
    (when (or (not can-omit) (not (eq? offset 1)))
      (push-instr! bc (list 'JMP 0 offset)))))

;;;;; Destination driven code generation ;;;;;;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Note code is generated bottom-up, last sexp to first.


;; f - the sexp we're generating code for
;; bc - the function's already emitted bytecode.
;; rd - the destination register.
;;      #f - effect context, no register required.
;;      number - specific destination register must be used, for things like LET, CALL, CLOSURE
;;
;;  Note that 'exp-loc' is used to kinda specify an 'any reg', testing if we can just use the current loc.
;;      Maybe add a real:
;;      'any - any register may be used, for things like ADD that can use any temporary.
;;
;;
;; nr - next available free register, which may or may not be equal to rd.
;;      All instructions are three-address, where one of the operands may equal the destination.
;;
;; cd - control destination.
;;      'ret - the return destination.  Also used for detecting tail calls.
;;      'next - next instruction.  Nothing special must be done.
;;       number - jump to this instruction.  (we should check if we actually need a jump, or it is the next instruction)
;;       (if number number) - branch destination. Jump to first num if true, second if false.
;; 

(define (finish bc cd nr r)
  (cond
   ((eq? cd 'ret)
    (push-instr! bc (list 'RET1 r)))
   ((number? cd)
    (build-jmp cd bc #t))
   ((branch-dest? cd)
    (emit-branch-try-invert 'JISF bc cd nr r 0))
   ((eq? cd 'next))
   (else (dformat "UNKNOWN CONTROL DEST:~a" cd) (exit -1))))

(define (compile-self-evaluating f bc rd nr cd)
  ;; If a constant has a branch destination, the result is unused,
  ;; and we can branch directly based on the constant value.
  ;;
  ;; This is important for 'and' and 'or' operators.
  ;;(dformat "Compile self eval ~a rd ~a cd ~a\n" f rd cd)
  (if (branch-dest? cd)
      (begin
	(if f
	    (build-jmp (second cd) bc #t)
	    (build-jmp (third cd) bc #t)))
      (begin
	(finish bc cd (if rd (+ 1 rd) nr) rd)))
  (when rd
	  (if (and  (fixnum? f) (< (abs f) 32768))
	      (push-instr! bc (list 'KSHORT rd f))
	      (let ((c (get-or-push-const bc f)))
		(push-instr! bc (list 'KONST rd c))))))

;; Drop leading '$' and standard-case it.
(define (symbol-to-bytecode x)
  (string->symbol (list->string (map char-standard-case (cdr (string->list (symbol->string x)))))))

(define quick-branch '($< $= $eq $> $<= $>= $guard $eqv?))
(define has-effect '($set-box! $apply $write $write-u8))
(define (compile-binary f bc env rd nr cd)
  (define vn '($- $+ $guard $closure-get))
  ;;(dformat "compile-binary ~a rd ~a\n" f rd)
  ;(if (and (not (memq (first f) has-effect)) (not rd)) (dformat "Dropping for effect context: ~a\n" f))
  (if (and (memq (first f) vn)
	   (fixnum? (third f))
	   (< (abs (third f)) 128))
      (compile-binary-vn f bc env rd nr cd)
      (compile-binary-vv f bc env rd nr cd)))

(define cmp-invert '((JISGT JISLTE) (JISLTE JISGT) (JISGTE JISLT) (JISLT JISGTE) (JISF JIST)
		     (JEQ JNEQ) (JEQV JNEQV) (JISEQ JISNEQ)
		     (JGUARD JNGUARD)))
(define (emit-branch-try-invert op bc cd nr r1 r2)
  ;;(dformat "try invert op ~a cd ~a len ~a\n" op cd (length (func-bc-code bc)))
  (if (and (assq op cmp-invert) (= (third cd) (length (func-bc-code bc))))
      (begin
	(build-jmp (third cd) bc #t)
	(build-jmp (second cd) bc #f)
	(push-instr! bc (list (second (assq op cmp-invert)) nr r1 r2)))
      (begin
	(build-jmp (second cd) bc #t)
	(build-jmp (third cd) bc #f)
	(push-instr! bc (list op nr r1 r2)))))

(define (compile-binary-vv f bc env rd nr cd)
  (define op (let ((op (if (and (not rd) (branch-dest? cd) (memq (first f) quick-branch))
			   ;; TODO clean these up in symbol-to-bytecode?
			 (assq (first f)
			       '(($< JISLT) ($= JISEQ)
				 ($> JISGT)
				 ($<= JISLTE)
				 ($>= JISGTE)
				 ($eq JEQ)
				 ($eqv? JEQV)))
			 (assq (first f)
			       '(($+ ADDVV) ($- SUBVV) ($< ISLT) ($> ISGT)
				 ($<= ISLTE) ($>= ISGTE)
				 ($* MULVV)
				 ($= ISEQ)
				 ($/ DIV)
				 ($% REM))))))
	       (if op (second op) (symbol-to-bytecode (car f)))))
  ;;(dformat "compile binary vv ~a rd ~a\n" f rd)
  (let* ((r1 (exp-loc (second f) env nr))
	 (r2 (exp-loc (third f) env (max nr (+ r1 1)))))
    (if (or rd (branch-dest? cd) (memq (first f) has-effect))
      (begin
	(if (and (not rd) (branch-dest? cd) (memq (first f) quick-branch))
	    (emit-branch-try-invert op bc cd nr r1 r2)
	    (begin
	      (finish bc cd (if rd (+ 1 rd) nr) (if rd rd nr))
	      (push-instr! bc (list op (if rd rd nr) r1 r2))))
	(compile-sexp (third f) bc env r2 (max r2 r1 nr) 'next)
	(compile-sexp (second f) bc env r1 (max nr r1) 'next))
      (finish bc cd (if rd (+ 1 rd) nr) rd))))

(define (compile-binary-vn f bc env rd nr cd)
  (define op (let ((op (if (and (not rd) (branch-dest? cd) (memq (first f) quick-branch))
			   (assq (first f)
				 '(($guard JGUARD)))
			   (assq (first f)
				 '(($+ ADDVN) ($- SUBVN))))))
	       (if op (second op) (symbol-to-bytecode (car f)))))
  (define r1 (exp-loc (second f) env nr))
  (if (and (not rd) (branch-dest? cd) (memq (first f) quick-branch))
      (emit-branch-try-invert op bc cd nr r1 (third f))
      (begin
	(finish bc cd (if rd (+ 1 rd) nr) (if rd rd nr))
	(push-instr! bc (list op (if rd rd nr) r1 (modulo (third f) 256)))))
  (compile-sexp (second f) bc env r1 r1 'next))

(define (compile-unary f bc env rd nr cd)
  (define op (symbol-to-bytecode (car f)))
  (define r1 (exp-loc (second f) env nr))
  ;;(if (not rd) (dformat "Dropping for effect context unary: ~a\n" f))
  (finish bc cd (if rd (+ 1 rd) nr) (if rd rd nr))
  (push-instr! bc (list op (if rd rd nr) r1))
  (compile-sexp (second f) bc env r1 (max nr r1) 'next))

(define (compile-if f bc env rd nr cd)
  (define dest (cond
		((eq? cd 'ret) cd)
		((branch-dest? cd) cd)
		((number? cd) cd)
		((eq? cd 'next)
		 (length (func-bc-code bc)))))
  (when (= 3 (length f)) ;; TODO remove, direct jump?
    (set! f (append f (list #f))))
  ;; branches with #t or #f in the 'then' or 'else' clauses without
  ;; a register destination (so for effect only), will forward the
  ;; branch destination.
  (when (or rd (not (and (branch-dest? cd) (boolean? (fourth f)))))
    (compile-sexp (fourth f) bc env rd nr dest))
  (let ((pos (length (func-bc-code bc))))
    (when (or rd (not (and (branch-dest? cd) (boolean? (third f)))))
      (compile-sexp (third f) bc env rd nr dest))
    ;; Forward branch destination for simple then/else clauses
    (let ((true-dest
	   (if (and (not rd) (branch-dest? cd) (boolean? (third f)))
	       (if (third f) (second cd) (third cd))
	       (length (func-bc-code bc))))
	  (false-dest
	   (if (and (not rd) (branch-dest? cd) (boolean? (fourth f)))
	       (if (fourth f) (second cd) (third cd))
	       pos)))
      (compile-sexp (second f) bc env #f nr `(if ,true-dest ,false-dest)))))

(define (compile-lambda f bc rd nr cd)
  (define f-bc (make-func-bc (second f) '() ))
  (define f-id (length program))
  ;(if (not rd) (dformat "Dropping for effect context: ~a\n" f))
  (push! program f-bc)
  (compile-lambda-internal (cons 'lambda (cddr f)) f-bc '())
  (finish bc cd (if rd (+ 1 rd) nr) rd)
  (dformat "Compile lambda ~a\n" f)
  (push-instr! bc (list 'KFUNC rd f-id)))

(define (ilength l)
  (if (null? l) 0
      (if (atom? l) 1
	  (+ 1 (ilength (cdr l))))))

(define (compile-cases f bc env rd nr cd)
  (if (not (eq? '$case (car f)))
      (compile-sexp f bc env rd nr cd)
      (let ((rest (improper? (second f))))
	(compile-cases (fourth f) bc env rd nr cd)
	(fold (lambda (n num)
		(push! env (cons n num))
		(+ num 1))
	      1 ;; closure var
	      (to-proper (second f)))
	(let ((next-case (length (func-bc-code bc)))
	      (r (+ 1 (ilength (second f)))))
	  (compile-sexp (third f) bc env r r cd)
	  (build-jmp next-case bc #f)
	  (push-instr! bc
		       (if rest (list 'CLFUNCV (- r 1) 1)
			   (list 'CLFUNC r 0)))))))

(define (compile-lambda-internal f f-bc env)
  (define r (ilength (second f)))
  (define rest (improper? (second f)))
  (define cl (and (pair? (third f)) (eq? '$case (car (third f)))))
  (when (not (= 3 (length f)))
    (dformat "ERROR invalid length lambda: ~a\n" f))
  ;;(dformat "Compile lambda ~a ~a\n" cl f)
  ;; Check for case-lambda
  (when (not cl)
    (fold (lambda (n num)
	    (push! env (cons n num))
	    (+ num 1))
	  0
	  (to-proper (second f))))
  (if cl
      (begin
	(push! env (cons (first (second f)) 0)) ; closure var for case-lambda
	(compile-cases (third f) f-bc env 1 1 'ret))
      (compile-sexp (third f) f-bc env r r 'ret))
  (when (not cl)
    (push-instr! f-bc
		 (if rest (list 'FUNCV (- r 1) 1)
		     (list 'FUNC r 0)))))

(define (exp-loc f env rd)
  (if (symbol? f)
      (or (find-symbol f env) rd)
      rd))

(define (find-symbol f env)
  (define l (assq f env))
  (if l (cdr l) #f))

(define (loop-var? f env)
  (define l (assq f env))
  (and l (pair? (cdr l))))

(define (compile-lookup f bc env rd nr cd)
  ;;(if (not rd) (dformat "Dropping for effect context: ~a\n" f))
  ;;(dformat "Compile lookup ~a rd ~a\n" f rd)
  (if rd
    (let ((loc (find-symbol f env))
	  (r (if (eq? cd 'ret) (exp-loc f env rd) rd)))
      (finish bc cd (+ 1 rd) r)
      (if loc
	  (when (not (= loc r))
	    (push-instr! bc (list 'MOV r loc)))
	  (let* ((c (get-or-push-const bc f)))
	    (push-instr! bc (list 'GGET r c)))))
    (if (branch-dest? cd)
	(let ((loc (find-symbol f env)))
	  (if loc
	      (finish bc cd nr loc)
	      (begin
		(finish bc cd nr nr)
		(push-instr! bc (list 'GGET nr (get-or-push-const bc f))))))
	(finish bc cd nr rd))))

;; Note we implicitly add the closure param here.
;; TODO optimize better for known calls.
(define (compile-call f bc env rd nr cd)
  ;;(dformat "Compile-call ~a rd ~a\n" f rd)
  (if (loop-var? (car f) env)
      (let* ((loop-info (cdr (assq (car f) env)))
	     (offset (- nr (car loop-info)))
	     (instr (list 'JMP 0 (length (func-bc-code bc)))))
	;;(dformat "Compile loop call: ~a nr ~a\n" f nr)
	(push-instr! bc instr)
	(set-cdr! loop-info (cons instr (cdr loop-info)))
	(fold
	 (lambda (f num)
	   (push-instr! bc (list 'MOV (- num offset) num))
	   (- num 1))
	 (+ (length f) nr -2)
	 (reverse (cdr f)))
	(fold
	 (lambda (f num)
	   (compile-sexp f bc env num num 'next)
	   (- num 1))
	 (+ (length f) nr -2)
	 (reverse (cdr f))))
      (begin
	(finish bc cd (if rd (+ 1 rd) nr) (if rd rd nr))
	(when (and rd (not (= rd nr)))
	  (push-instr! bc (list 'MOV rd nr)))
	(push-instr! bc (list (if (eq? cd 'ret) 'CALLT 'CALL) nr (+ 1 (length f))))
	(fold
	 (lambda (f num)
	   (compile-sexp f bc env num num 'next)
	   (- num 1))
	 (+ (length f) nr)
	 (reverse f)))))

(define labels '())
(define (compile-label-call f bc env rd nr cd)
  ;; Only emit closure if needed
  ;; Check for null closure
  (define args (if (third f) (cddr f) (cdddr f)))
  (finish bc cd (if rd (+ 1 rd) nr) (if rd rd nr))
  (when (and rd (not (= rd nr)))
    (push-instr! bc (list 'MOV rd nr)))
  (push-instr! bc (list (if (eq? cd 'ret) 'LCALLT 'LCALL) nr (+ 1 (length args))))
  ;;(dformat "labels: ~a\n" labels)
  ;;(dformat "Label call: ~a  args ~a nr ~a\n" f (length args) nr)
  (push-instr! bc (list 'KFUNC nr (cdr (assq (second f) labels))))
  (fold
   (lambda (f num)
     (compile-sexp f bc env num num 'next)
     (- num 1))
   (+ (length args) nr)
   (reverse args)))

(define (compile-label f bc env rd nr cd)
  (finish bc cd nr rd)
  ;;(dformat "Compile label ~a\n" f)
  (push-instr! bc (list 'KFUNC rd (cdr (assq (second f) labels)))))

(define (compile-labels f bc env rd nr cd)
  (define (compile-lambda f f-bc)
    (define lam (second f))
    (compile-lambda-internal (cons 'lambda (cddr lam)) f-bc '()))
  (let* ((cnt (length program))
	 (f-bc (map-in-order (lambda (f)
			       (let* ((lam (second f))
				      (f-bc (make-func-bc (second lam) '())))
				 (push! labels (cons (first f) cnt))
				 ;;(dformat "cnt label ~a ~a\n" (first f) cnt)
				 (push! program f-bc)
				 (set! cnt (+ 1 cnt))
				 f-bc))
			     (second f))))
    ;;(dformat "Compile labels ~a\n" (map car (second f)))
    (for-each compile-lambda (second f) f-bc)
    (compile-sexp (third f) bc env rd nr cd)))

(define (compile-const-closure f bc env rd nr cd)
  (finish bc cd rd rd)
  (let ((c (get-or-push-const bc f)))
    (push-instr! bc (list 'KONST rd c))))

(define (compile-vararg f bc env rd nr cd)
					;(if (not rd) (dformat "Dropping for effect context: ~a\n" f))
  ;;(if (not rd) (error "ERror compile-vararg"))
  (finish bc cd (if rd (+ 1 rd) nr) rd)
  (when (not (= rd nr))
    (push-instr! bc (list 'MOV rd nr)))
  (push-instr! bc (list (symbol-to-bytecode (car f)) nr (- (length f) 1)))
  (fold
   (lambda (f num)
     (compile-sexp f bc env num num 'next)
     (- num 1))
   (+ (length f) nr -2)
   (reverse (cdr f))))

;; Third arg must be immediate fixnum.
(define (compile-closure-set f bc env rd nr cd)
  ;(if (not rd) (error "ERror compile-closure-set"))
  (finish bc cd (if rd (+ 1 rd) nr) rd)
  (let* ((r1 (exp-loc (second f) env nr))
	(r2 (exp-loc (third f) env (max nr (+ r1 1)))))
    (push-instr! bc (list 'CLOSURE-SET r1 r2 (fourth f)))
    (compile-sexp (third f) bc env r2 (max nr r2 r1) 'next)
    (compile-sexp (second f) bc env r1 (max nr r1) 'next)))

;; First arg is register to use, k, then obj
(define (compile-setter f bc env rd nr cd)
  ;(if (not rd) (error "ERror compile-setter"))
  (finish bc cd (if rd (+ 1 rd) nr) rd)
  (let* ((r1 (exp-loc (second f) env nr))
	(r2 (exp-loc (third f) env (max nr (+ r1 1))))
	(r3 (exp-loc (fourth f) env (max nr (+ r1 1) (+ r2 1)))))
    (push-instr! bc (list (if (eq? '$vector-set! (first f)) 'VECTOR-SET! 'STRING-SET!) r1 r2 r3))
    (compile-sexp (fourth f) bc env r3 (max nr r2 r1 r3) 'next)
    (compile-sexp (third f) bc env r2 (max nr r1 r2) 'next)
    (compile-sexp (second f) bc env r1 (max nr r1) 'next)))

(define (compile-setter2 f bc env rd nr cd)
  ;(if (not rd) (error "ERror compile-setter2"))
  (finish bc cd (if rd (+ 1 rd) nr) rd)
  (let* ((r1 (exp-loc (second f) env nr))
	(r2 (exp-loc (third f) env (max nr (+ r1 1)))))
    (push-instr! bc (list (if (eq? '$set-car! (first f)) 'SET-CAR! 'SET-CDR!) r1 r2))
    (compile-sexp (third f) bc env r2 (max nr r1 r2) 'next)
    (compile-sexp (second f) bc env r1 (max nr r1) 'next)))

(define (closure? f)
  (and (pair? f) (eq? '$closure (car f))))

(define (compile-define f bc env rd nr cd)
  (if (pair? (second f))
      (compile-define
       `(define ,(car (second f)) (lambda ,(cdr (second f)) ,@(cddr f)))
       bc env rd nr cd)
      (let* ((c (get-or-push-const bc (second f))))
	;; TODO undef
	;(if (not rd) (error "ERror compile-define"))
	(finish bc cd (if rd (+ 1 rd) nr) rd)
	(push-instr! bc (list 'GSET nr c))
	(compile-sexp (third f) bc env nr nr 'next))))

(define (compile-let f bc env rd nr cd)
  (let ((ord nr))
    (define orig-env env) ;; let values use original mapping
    (define mapping (map-in-order (lambda (f)
				    (define o ord)
				    (push! env (cons (first f) ord))
				    (inc! ord)
				    o)
				  (second f)))
    (when (not (= 3 (length f)))
      (dformat "ERROR invalid length let:\n")
      (display f)
      (newline)
      (exit -1))
    (compile-sexp (third f) bc env rd ord cd)
    ;; Do this in reverse, so that we don't smash register usage.
    (for-each (lambda (f r)
		(compile-sexp (second f) bc orig-env r r 'next))
	      (reverse (second f))
	      (reverse mapping))))

(define (compile-loop f bc env rd nr cd)
  (let ((ord nr))
    (define orig-env env) ;; let values use original mapping
    (define mapping (map-in-order (lambda (f)
				    (define o ord)
				    (push! env (cons f ord))
				    (inc! ord)
				    o)
				  (second f)))
    (define end (length (func-bc-code bc)))
    (define loop-info (cons nr '()))
    (push! env (cons (fourth f) loop-info))
    (compile-sexp (fifth f) bc env rd ord cd)
    (push-instr! bc (list 'LOOP nr (length (second f))))
    (for-each (lambda (instr) (set-car! (cddr instr) (- (caddr instr) (length (func-bc-code bc)) -1)))
	      (cdr loop-info))
    ;; Do this in reverse, so that we don't smash register usage.
    (for-each (lambda (f r)
		(compile-sexp f bc orig-env r r 'next))
	      (reverse (third f))
	      (reverse mapping))))

(define (compile-or f bc env rd nr cd)
  (define fin (length (func-bc-code bc)))
  ;;(dformat "compile or ~a rd ~a\n" f rd)
  (case (length f)
    ((1) (compile-sexp #f bc env rd nr cd))
    ((2) (compile-sexp (second f) bc env rd nr cd))
    (else
     (if (> (length f) 3)
	 (compile-or `(or ,@(cddr f)) bc env rd nr cd)
	 (compile-sexp (third f) bc env rd nr cd))
     (let* ((false-dest (length (func-bc-code bc)))
	    (r1 (if rd nr rd))
	    (true-dest (cond 
			((eq? cd 'ret) (push-instr! bc (list 'RET1 r1))
			 (length (func-bc-code bc)))
			((number? cd) cd)
			((branch-dest? cd)  (second cd))
			((eq? cd 'next)	 fin))))
       (compile-sexp (second f) bc env r1 nr `(if ,true-dest ,false-dest))))))

(define (bytecode? x)
  (and (symbol? x) (eq? #\$ (string-ref (symbol->string x) 0))))

(define (compile-sexp f bc env rd nr cd)
  ;;(dformat "SEXP: ~a rd ~a\n" f rd)
  (if (not (pair? f))
      (if (symbol? f)
	  (compile-lookup f bc env rd nr cd)
	  (compile-self-evaluating f bc rd nr cd))
      (case (car f)
	;; The standard scheme forms.
	((define) (compile-define f bc env rd nr cd))
	((let) (compile-let f bc env rd nr cd))
	((named-lambda) (compile-lambda f bc rd nr cd))
	((begin) (compile-sexps (cdr f) bc env rd nr cd))
	((if) (compile-if f bc env rd nr cd))
	((set!) (compile-define f bc env rd nr cd)) ;; TODO check?
	((quote) (compile-self-evaluating (second f) bc rd nr cd))
	((or) (compile-or f bc env rd nr cd))
	(($loop) (compile-loop f bc env rd nr cd))

	;; Builtins
	(($vector-set! $string-set!) (compile-setter f bc env rd nr cd))
	(($set-car! $set-cdr!) (compile-setter2 f bc env rd nr cd))
	(($closure $vector) (compile-vararg f bc env rd nr cd))
	(($const-closure) (compile-const-closure f bc env rd nr cd))
	(($closure-set) (compile-closure-set f bc env rd nr cd))
	(($label-call) (compile-label-call f bc env rd nr cd))
	(($labels) (compile-labels f bc env rd nr cd))
	(($label) (compile-label f bc env rd nr cd))
	(else
	 (if (bytecode? (car f))
	     (case (length f)
	       ((2) (compile-unary f bc env rd nr cd))
	       ((3) (compile-binary f bc env rd nr cd))
	       (else (error "Unknown bytecode op:" f)))
	     (compile-call f bc env rd nr cd))))))

(define (compile-sexps program bc env rd nr cd)
  (let loop ((program (reverse program)) (rd rd) (cd cd))
    (compile-sexp (car program) bc env rd nr cd) 
    (if (pair? (cdr program))
	(begin
	  (loop (cdr program) #f 'next))))) ;; All other statements are in effect context

(define (compile d)
  (define bc (make-func-bc "repl" '()))
  (push! program bc)
  ;;(display "Compile:\n")
  ;;(pretty-print d)
  ;;(newline)
  (compile-sexps d bc '() 0 0 'ret)
  (push-instr! bc (list 'FUNC 0 0)))

;;;;;;;;;;;;;expander
(define (read-file)
  (define (read-file-rec sexps)
    (define next (read))
    (if (eof-object? next)
	(let ((res (reverse sexps)))
	  ;(dformat "Expanding: ~a\n" res)
	  res)
      (read-file-rec (cons next sexps))))

  (read-file-rec '()))

(define store (null-mstore))
(define (expander )
  (expand-top-level-forms! (read-file) store))

;;;;;;;;;;;;;print
(define (display-bc bc)
  (define jmp-dst '())
  (dformat "~a:\n" (func-bc-name bc))
  (display "Code:\n")
  (fold (lambda (a b)
	  (define (str-op op) (define ops (symbol->string op)) (string-append ops (make-string (- 15 (string-length ops)) #\space)))
	  (dformat "~a: ~a\t~a~a" b (if (or (eq? (first a) 'LOOP) (memq b jmp-dst)) "==>" "") (str-op (first a)) (second a))
	  (if (> (length a) 2) (dformat "\t~a" (third a)))
	  (if (> (length a) 3) (dformat "\t~a" (fourth a)))
	  (let ((op (first a)))
	    (if (memq op '(GGET GSET KONST))
		(dformat  "\t ;; ~a" (list-ref consts (third a))))
	    (when (eq? op 'KFUNC)
	      (dformat "\t ;; ~a" (func-bc-name (list-ref program (third a)))))
	    (when (eq? op 'JMP)
	      (push! jmp-dst (+ b (third a)))
	      (dformat "\t ==> ~a" (+ b (third a)))))
	  
	  (newline)
	  (+ b 1))
	0 (func-bc-code bc))
  (newline))

;;;;;;;;;;;;;; serialize bc

(include "opcodes.scm")

(define bc-ins '(KSHORT GGET GSET KONST KFUNC JMP LOOP))

(define (write-uint v p)
  (write-u8 (mask-byte v) p)
  (write-u8 (mask-byte (arithmetic-shift v -8)) p)
  (write-u8 (mask-byte (arithmetic-shift v -16)) p)
  (write-u8 (mask-byte (arithmetic-shift v -24)) p))

(define (write-u64 v p)
  (write-u8 (mask-byte v) p)
  (write-u8 (mask-byte (arithmetic-shift v -8)) p)
  (write-u8 (mask-byte (arithmetic-shift v -16)) p)
  (write-u8 (mask-byte (arithmetic-shift v -24)) p)
  (write-u8 (mask-byte (arithmetic-shift v -32)) p)
  (write-u8 (mask-byte (arithmetic-shift v -40)) p)
  (write-u8 (mask-byte (arithmetic-shift v -48)) p)
  (write-u8 (mask-byte (arithmetic-shift v -56)) p))

(define (write-u16 v p)
  (write-u8 (mask-byte v) p)
  (write-u8 (mask-byte (arithmetic-shift v -8)) p))

(define symbol-table '())
(define (bc-write-const c p)
  (cond
   ((symbol? c)
    (let ((pos (find-const symbol-table (- (length symbol-table) 1) c)))
      (if pos
	  (write-u64 (+ symbol-tag (arithmetic-shift pos 3)) p)
	  (let* ((pos (length symbol-table))
		(str (symbol->string c))
		(len (string-length str)))
	    (push! symbol-table c)
	    (write-u64 (+ symbol-tag (arithmetic-shift pos 3)) p)
	    (write-u64 len p)
	    (for-each (lambda (c) (write-u8 (char->integer c) p)) (string->list str))))))
   ((flonum? c)
    (write-u64 flonum-tag p)
    (write-double c p))
   ((and  (fixnum? c))
    (write-u64 (* 8 c) p))
   ((char? c)
    (write-u64 (+ char-tag (arithmetic-shift (char->integer c) 8)) p))
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
    (write-u64 vector-tag p)
    (write-u64 (vector-length c) p)
    (do ((i 0 (+ i 1)))
	((= i (vector-length c)))
      (bc-write-const (vector-ref c i) p)))
   ((and (pair? c) (eq? '$const-closure (car c)))
    (write-u64 closure-tag p)
    (write-u64 (cdr (assq (second (second c)) labels)) p))
   ((pair? c)
    (write-u64 cons-tag p)
    (bc-write-const (car c) p)
    (bc-write-const (cdr c) p))
   (else (dformat "Can't serialize: ~a\n" c)
	 (write-u64 0 p)
	 ;(exit -1)
	 )))

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
     ;;(display "BC:") (display bc) (newline)
     (write-uint (string-length (func-bc-name bc)) p)
     (for-each (lambda (c) (write-u8 (char->integer c) p)) (string->list (func-bc-name bc)))
     (write-uint (length (func-bc-code bc)) p)
     (for-each
      (lambda (c)
	(define ins (assq (first c) opcodes))
	(when (not ins)
	  (dformat "ERROR could not find ins ~a\n" c)
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
(define (add-includes lst)
  (define (includes sexp)
    (if (and (pair? sexp) (eq? 'include (car sexp)))
	(begin
	  ;;(display "Found include:") (display sexp) (newline)
	  (add-includes (with-input-from-file (second sexp) (lambda () (expander)))))
	(list sexp)))
  (if (pair? lst)
      (let ((included (includes (car lst))))
	(append included (add-includes (cdr lst))))
      '()))

(define (compile-file name . rest)
  (define (debugdisplay src)
    (when (pair? rest)
      (newline)
      (display "Compiling:\n")
      (pretty-print src)
      (newline))
    src)
  (set! consts '(
		 ))
  (set! const-length 0)
  (set! symbol-table '())
  (set! program '())
  (-> (with-input-from-file name expander)
      add-includes ;;  Can remove with new expander
      case-insensitive ;; Can remove with new expander
      integrate-r5rs ;; optional
      alpha-rename ;;  Can remove with new expander
      fix-letrec
      assignment-conversion
      optimize-direct ;; optional
      lower-case-lambda ;; Can remove with new expander? 
      lower-loops ;; optional
      name-lambdas
      ;; Closure conversion passes
      letrec-ify-prepass

      find-free

      update-direct-calls

      scletrec

      scletrec2

      final-free

      closure-conversion-scc
      debugdisplay
;      closure-conversion
;      debugdisplay
      compile
      )


  ;; Get everything in correct order
  ;; TODO do this as we are generating with extendable vectors
  (set! consts (reverse! consts))
  (set! program (reverse! program))

  (when (pair? rest)
    (display "Consts:\n")
    (fold (lambda (a b)
	    (dformat "~a: ~a\n" b a)
	    (+ b 1))
	  0 consts)
    (newline)
    (fold (lambda (a b)
	    (dformat "~a -- " b)
	    (display-bc a)
	    (+ b 1))
	  0
	  program))

  (bc-write (string-append name ".bc") program))

