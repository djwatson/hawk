;;;;;;;;;;;;; include

(include "third-party/alexpander.scm")
(include "memory_layout.scm")
(include "passes.scm")

;;;;;;;;;;;;;;;;; util
(define (mask-byte b)
  (modulo b 256))

(define (dformat format-string . objects)
  (define (format-error message)
    (error message format-string))
  (let loop ((format-list (string->list format-string))
             (objects objects))
    (cond ((null? format-list) #f) ;; done
          ((char=? (car format-list) #\~)
           (if (null? (cdr format-list))
               (format-error "Incomplete escape sequence")
               (case (cadr format-list)
                 ((#\a)
                  (if (null? objects)
                      (format-error "No value for escape sequence")
                      (begin
                        (display (car objects))
                        (loop (cddr format-list) (cdr objects)))))
                 ((#\s)
                  (if (null? objects)
                      (format-error "No value for escape sequence")
                      (begin
                        (write (car objects))
                        (loop (cddr format-list) (cdr objects)))))
                 ((#\%)
                  (newline)
                  (loop (cddr format-list) objects))
                 ((#\~)
                  (write-char #\~)
                  (loop (cddr format-list) objects))
                 (else
                  (format-error "Unrecognized escape sequence")))))
          (else (write-char (car format-list))
                (loop (cdr format-list) objects)))))

(define (arithmetic-shift n count)
  (if (negative? count)
      (let ((k (expt 2 (- count))))
        (if (negative? n)
            (+ -1 (quotient (+ 1 n) k))
            (quotient n k)))
      (* (expt 2 count) n)))
(define-syntax when
  (syntax-rules ()
    ((_ cond body ...)
     (if cond (begin body ...)))))
(define (map-in-order f list)
  (let recur ((lis list))
    (if (null? lis) lis
	(let ((tail (cdr lis))
	      (x (f (car lis))))
	  (cons x (recur tail))))))
(define (fold kons knil lis1 )
  (let lp ((lis lis1) (ans knil))	; Fast path
    (if (null? lis) ans
	(lp (cdr lis) (kons (car lis) ans)))))
(define (element? x lst)
  (cond ((null? lst) #f)
        ((equal? x (car lst)) #t)
        (#t (element? x (cdr lst)))))
(define (union a b)
  (cond ((null? b) a)
        ((element? (car b) a)
         (union a (cdr b)))
        (#t (union (cons (car b) a) (cdr b)))))
(define (difference a b)
  (cond ((null? a) '())
        ((element? (car a) b)
         (difference (cdr a) b))
        (#t (cons (car a) (difference (cdr a) b)))))
(define first car)
(define (second f) (cadr f))
(define (third f) (caddr f))
(define (fourth f) (cadddr f))
(define (reverse! lis)
  (let lp ((lis lis) (ans '()))
    (if (null? lis) ans
        (let ((tail (cdr lis)))
          (set-cdr! lis ans)
          (lp tail lis)))))
(define (iota count )
  (if (< count 0) (error "Negative step count" iota count))
  (let ((start 0) (step 1))
    (let loop ((n 0) (r '()))
      (if (= n count)
	  (reverse r)
	  (loop (+ 1 n)
		(cons (+ start (* n step)) r))))))
(define (filter-map f list1 . list2)
  (if (not (pair? list2))
      (let recur ((lis list1))
	(if (null? lis) lis
	    (let ((tail (recur (cdr lis))))
	      (cond ((f (car lis)) => (lambda (x) (cons x tail)))
		    (else tail)))))
      (let recur ((lis1 list1) (lis2 (car list2)))
	(if (or (null? lis2) (null? lis1)) '()
	    (let ((tail (recur (cdr lis1) (cdr lis2))))
	      (cond ((f (car lis1) (car lis2)) => (lambda (x) (cons x tail)))
		    (else tail)))))))
  
(define (filter pred lis)			; Sleazing with EQ? makes this
  (let recur ((lis lis))
    (if (null? lis) lis			; Use NOT-PAIR? to handle dotted lists.
	(let ((head (car lis))
	      (tail (cdr lis)))
	  (if (pred head)
	      (let ((new-tail (recur tail)))	; Replicate the RECUR call so
		(if (eq? tail new-tail) lis
		    (cons head new-tail)))
	      (recur tail))))))		
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

;; TODO pass around in a state struct
(define cur-name "")

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

(define (build-jmp offset)
  (when (or (<= offset 0) (> offset 65535))
    (dformat "OFFSET too big: ~a\n" offset)
    (exit -1))
  (list 'JMP 0 offset))

(define (finish bc cd r)
  (cond
   ((eq? cd 'ret)
    (push-instr! bc (list 'RET1 r)))
   ((number? cd)
    (let ((jlen (- (length (func-bc-code bc)) cd -1)))
	    (when (not (eq? jlen 1))
	      (push-instr! bc (build-jmp jlen)))))
   ((branch-dest? cd)
      (push-instr! bc (build-jmp (third cd)))
      (push-instr! bc (list 'ISF r)))
   ((eq? cd 'next))
   (else (dformat "UNKNOWN CONTROL DEST:~a" cd) (exit -1))))

(define (compile-self-evaluating f bc rd cd)
  ;; TODO save len
  (when cd
    (finish bc cd rd)
    (if (and  (fixnum? f) (< (abs f) 32768))
	(push-instr! bc (list 'KSHORT rd f))
	(let ((c (get-or-push-const bc f)))
	  (push-instr! bc (list 'KONST rd c))))))

(define (compile-binary f bc env rd cd)
  (define vn '($- $+ $guard $closure-get))
  (if (and (memq (first f) vn)
	   (fixnum? (third f))
	   (< (abs (third f)) 128))
      (compile-binary-vn f bc env rd cd)
      (compile-binary-vv f bc env rd cd)))

(define (compile-binary-vv f bc env rd cd)
  (define op (second (if (and #f (branch-dest? cd))
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
				 ($apply APPLY)
				 ($/ DIV)
				 ($% REM)
				 ($callcc-resume CALLCC-RESUME)
				 ($open OPEN)
				 ($write WRITE)
				 ($write-u8 WRITE-U8))))))
  (let* ((r1 (exp-loc (second f) env rd))
	(r2 (exp-loc (third f) env (max rd (+ r1 1)))))
    (when cd
      (if (and #f (branch-dest? cd))
	  (push-instr! bc (build-jmp (third cd)))
	  (finish bc cd rd))
      (push-instr! bc (list op rd r1 r2))
      (compile-sexp (third f) bc env r2 'next)
      (compile-sexp (second f) bc env r1 'next))))

(define (compile-binary-vn f bc env rd cd)
  (define op (second (assq (first f)
			   '(($+ ADDVN) ($- SUBVN)
			     ($guard GUARD) ($closure CLOSURE) ($closure-get CLOSURE-GET)))))
  (define r1 (exp-loc (second f) env rd))
  (when cd
    (finish bc cd rd)
    (push-instr! bc (list op rd r1 (third f)))
    (compile-sexp (second f) bc env r1 'next)))

(define (compile-unary f bc env rd cd)
  (define op (second (assq (first f)
			   '(($box BOX) ($unbox UNBOX)
			     ($car CAR) ($cdr CDR)
			     ($vector-length VECTOR-LENGTH)
			     ($string-length STRING-LENGTH)
			     ($symbol->string SYMBOL-STRING)
			     ($string->symbol STRING-SYMBOL)
			     ($char->integer CHAR-INTEGER)
			     ($integer->char INTEGER-CHAR)
			     ($callcc CALLCC)
			     ($read READ)
			     ($peek PEEK)
			     ($close CLOSE)))))
  (define r1 (exp-loc (second f) env rd))
  (when cd
    (finish bc cd rd)
    (push-instr! bc (list op rd r1))
    (compile-sexp (second f) bc env r1 'next)))

(define (compile-if f bc env rd cd)
  (define dest (cond
		((eq? cd 'ret) cd)
		((branch-dest? cd)
		 (push-instr! bc (build-jmp (third cd)))
		 (push-instr! bc (list 'ISF rd))
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
  (define f-bc (make-func-bc cur-name '() ))
  (define f-id (length program))
  (define old-name cur-name)
  (set! cur-name (string-append cur-name  "-lambda"))
  (push! program f-bc)
  (compile-lambda-internal f f-bc '())
  (finish bc cd rd)
  (push-instr! bc (list 'KFUNC rd f-id))
  (set! old-name cur-name))

(define (ilength l)
  (if (null? l) 0
      (if (atom? l) 1
	  (+ 1 (ilength (cdr l))))))

(define (compile-lambda-internal f f-bc env)
  (define r (ilength (second f)))
  (define rest (improper? (second f)))
  (fold (lambda (n num)
	  (push! env (cons n num))
	  (+ num 1))
	0
	(to-proper (second f)))
  (compile-sexps (cddr f) f-bc env r 'ret)
  (push-instr! f-bc
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
  (define r (if (eq? cd 'ret) (exp-loc f env rd) rd))
  (finish bc cd r)
  (if loc
      (when (not (= loc r))
	(push-instr! bc (list 'MOV loc r)))
      (let* ((c (get-or-push-const bc f)))
	(push-instr! bc (list 'GGET r c)))))

;; Note we implicitly add the closure param here.
;; TODO optimize better for known calls.
(define (compile-call f bc env rd cd)
  (finish bc cd rd)
  (push-instr! bc (list (if (eq? cd 'ret) 'CALLT 'CALL) rd (+ 1 (length f))))
  (push-instr! bc (list 'CLOSURE-PTR rd (+ rd 1)))
  (fold
   (lambda (f num)
     (compile-sexp f bc env num 'next)
     (- num 1))
   (+ (length f) rd)
   (reverse f)))

(define (compile-closure f bc env rd cd)
  (finish bc cd rd)
  (push-instr! bc (list 'CLOSURE rd (- (length f) 1)))
  (fold
   (lambda (f num)
     (compile-sexp f bc env num 'next)
     (- num 1))
   (+ (length f) rd -2)
   (reverse (cdr f))))

;; Third arg must be immediate fixnum.
(define (compile-closure-set f bc env rd cd)
  (finish bc cd rd)
  (let* ((r1 (exp-loc (second f) env rd))
	(r2 (exp-loc (third f) env (max rd (+ r1 1)))))
    (push-instr! bc (list 'CLOSURE-SET r1 r2 (fourth f)))
    (compile-sexp (third f) bc env r2 'next)
    (compile-sexp (second f) bc env r1 'next)))

;; First arg is register to use, k, then obj
(define (compile-setter f bc env rd cd)
  (finish bc cd rd)
  (let* ((r1 (exp-loc (second f) env rd))
	(r2 (exp-loc (third f) env (max rd (+ r1 1))))
	(r3 (exp-loc (fourth f) env (max rd (+ r2 1)))))
    (push-instr! bc (list (if (eq? '$vector-set! (first f)) 'VECTOR-SET 'STRING-SET) r1 r2 r3))
    (compile-sexp (fourth f) bc env r3 'next)
    (compile-sexp (third f) bc env r2 'next)
    (compile-sexp (second f) bc env r1 'next)))

(define (compile-setter2 f bc env rd cd)
  (finish bc cd rd)
  (let* ((r1 (exp-loc (second f) env rd))
	(r2 (exp-loc (third f) env (max rd (+ r1 1)))))
    (push-instr! bc (list (if (eq? '$set-car! (first f)) 'SET-CAR 'SET-CDR) r1 r2))
    (compile-sexp (third f) bc env r2 'next)
    (compile-sexp (second f) bc env r1 'next)))

(define (closure? f)
  (and (pair? f) (eq? '$closure (car f))))

(define (compile-define f bc env rd cd)
  (if (pair? (second f))
      (compile-define
       `(define ,(car (second f)) (lambda ,(cdr (second f)) ,@(cddr f)))
       bc env rd cd)
      (let* ((c (get-or-push-const bc (second f)))
	     (old-name cur-name))
	(when (closure? (third f))
	  (set! cur-name (symbol->string (second f))))
	;; TODO undef
	(finish bc cd rd)
	(push-instr! bc (list 'GSET rd c))
	(compile-sexp (third f) bc env rd 'next)
	(set! cur-name old-name)
	)))

(define (compile-let f bc env rd cd)
  (let ((ord rd))
    (define orig-env env) ;; let values use original mapping
    (define mapping (map-in-order (lambda (f)
				    (define o ord)
				    (push! env (cons (first f) ord))
				    (inc! ord)
				    o)
				  (second f)))
    ;; TODO without mov?
    (if (and cd (not (eq? cd 'ret)))
	(begin
	  (finish bc cd rd)
	  (push-instr! bc (list 'MOV ord rd))
	  (compile-sexps (cddr f) bc env ord 'next))
	(compile-sexps (cddr f) bc env ord cd)
	)
    ;; Do this in reverse, so that we don't smash register usage.
    (for-each (lambda (f r)
		(define old-name cur-name)
		(when (closure? (second f)) (set! cur-name (symbol->string (first f))))
		(compile-sexp (second f) bc orig-env r 'next)
		(set! cur-name old-name))
	      (reverse (second f))
	      (reverse mapping))))

(define (compile-sexp f bc env rd cd)
  ;;(display "SEXP:") (display f) (newline)
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
	     $make-vector $vector-ref $make-string $string-ref $apply
	     $/ $% $callcc-resume $open $write $write-u8)
	 (compile-binary f bc env rd cd))
	(($vector-set! $string-set!) (compile-setter f bc env rd cd))
	(($set-car! $set-cdr!) (compile-setter2 f bc env rd cd))
	(($box $unbox $car $cdr $vector-length $display $string-length
	       $symbol->string $string->symbol $char->integer $integer->char
	       $callcc $read $peek $close)
	 (compile-unary f bc env rd cd))
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
  ;;(display "Compile:\n")
  ;;(pretty-print d)
  ;;(newline)
  (compile-sexps d bc '() 0 'ret)
  (push-instr! bc (list 'FUNC 0 0)))

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
  (dformat "~a:\n" (func-bc-name bc))
  (display "Code:\n")
  (fold (lambda (a b)
	  (dformat "~a: ~a\n" b a)
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
	       (WRITE 44)
	       (STRING-LENGTH 45)
	       (STRING-REF 46)
	       (STRING-SET 47)
	       (MAKE-STRING 48)
	       (APPLY 49)
	       (SYMBOL-STRING 50)
	       (STRING-SYMBOL 51)
	       (CHAR-INTEGER 52)
	       (INTEGER-CHAR 53)
	       (REM 54)
	       (DIV 55)
	       (CALLCC 56)
	       (CALLCC-RESUME 57)
	       (OPEN 58)
	       (CLOSE 59)
	       (READ 60)
	       (PEEK 61)
	       (WRITE-U8 62)))

(define bc-ins '(KSHORT GGET GSET KONST KFUNC JMP))

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
    (write-u64 (write-double c) p))
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
	(define ins (assq (first c) enum))
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

(define bootstrap (with-input-from-file "bootstrap.scm" (lambda () (expander))))

;(pretty-print (assignment-conversion (fix-letrec (expander))))


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

(define opt (closure-conversion
	  (optimize-direct
	   (assignment-conversion
	    (fix-letrec
	     (alpha-rename
	      (integrate-r5rs
	       (case-insensitive
		(add-includes
		 (append bootstrap (expander))
		 #;(expander)
		 )))))))))
;(display "Compiling:\n") (pretty-print opt) (newline)
(compile opt)
;; Get everything in correct order
;; TODO do this as we are generating with extendable vectors
(set! consts (reverse! consts))
(set! program (reverse! program))

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
      program)

(bc-write "out.bc" program)

