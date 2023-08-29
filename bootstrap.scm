;;; Some crap to get case-lambda by alexpander, and some other passes.

(define-syntax case-lambda
  (syntax-rules ()
    ((_ (args body ...) ...)
     ($case-lambda (lambda args body ...) ...))))

(define (error reason . args)
      (display "Error: ")
      (display reason)
      (for-each (lambda (arg) 
                  (display " ")
		  (write arg))
		args)
      (newline)
      (car -1))
;;These have to match memory_layout.scm and types.h.
(define (number? x) (or (fixnum? x) (flonum? x)))
(define (flonum? x) ($guard x 2))
(define (fixnum? x) ($guard x 0))
(define (null? x) ($guard x #x14))
(define (boolean? x) ($guard x #x04))
(define (char? x) ($guard x #x0c))
(define (pair? x) ($guard x 3))
(define (procedure? x) ($guard x 5))
(define (symbol? x) ($guard x 6))
(define (vector? x) ($guard x #x11))
(define (string? x) ($guard x 9))
(define (port? x) ($guard x #x19))
(define complex? number?)
(define real? number?)
(define rational? number?)
(define integer? fixnum?)
(define exact? fixnum?)
(define inexact? flonum?)
(define exact-integer? fixnum?)

(define (reducer f init args)
  (let loop ((init init) (args args))
    (if (pair? args)
	(loop (f init (car args)) (cdr args))
	init)))
(define +
  (case-lambda
   (() 0)
   ((a) a)
   ((a b) ($+ a b))
   (rest (reducer (lambda (a b) ($+ a b)) 0 rest))))
(define -
  (case-lambda
   ((a) (* -1 a))
   ((a b) ($- a b))
   ((a . rest) (reducer (lambda (a b) ($- a b)) a rest))))

(define *
  (case-lambda
   ((a) a)
   ((a b) ($* a b))
   ((a b c) ($* ($* a b) c))
   (rest (reducer
     (lambda (a b) ($* a b))
     1
     rest))))
(define (comparer f args)
  (let loop ((args args))
    (if (and (pair? args) (pair? (cdr args)))
	(if (f (car args) (cadr args))
	    (loop (cdr args))
	    #f)
	#t)))
(define /
  (case-lambda
   ((a) ($/ 1 a))
   ((a b) ($/ a b))
   ((a . rest) (reducer
	     (lambda (a b) ($/ a b))
	     a
	     rest))))
(define (quotient x y)
  (exact (/ x y)))
(define (modulo x y)
  (let ((z (remainder x y)))
    (if (negative? y)
	(if (positive? z) (+ z y) z)
	(if (negative? z) (+ z y) z))))
(define (remainder a b) ($% a b))

(define gcd
  (case-lambda
   (() 0)
   ((a) a)
   ((a b)
    (if (= b 0)
      (abs a)
      (gcd b (remainder a b))))
   (args (let lp ((x (car args)) (ls (cdr args)))
        (if (null? ls) x (lp (gcd x (car ls)) (cdr ls)))))))

(define lcm
  (case-lambda
   (() 1)
   ((a) a)
   ((a b) (abs (quotient (* a b) (gcd a b))))
   (args (let lp ((x (car args)) (ls (cdr args)))
        (if (null? ls) x (lp (lcm x (car ls)) (cdr ls)))))))

;; TODO probably needs to work on flonum too.
(define (expt num exp)
  (if (> exp 0)
      (let loop ((n 1) (cnt exp))
	(if (= cnt 0) n
	    (loop (* num n) (- cnt 1))))
      (let loop ((n 1.0) (cnt exp))
	(if (= cnt 0) n
	    (loop (/ n num) (+ cnt 1))))))


(define <
  (case-lambda
   ((a b) ($< a b))
   (rest
    (comparer (lambda (a b) ($< a b)) rest))))
(define >
  (case-lambda
   ((a b) ($> a b))
   (rest
    (comparer (lambda (a b) ($> a b)) rest))))
(define <=
  (case-lambda
   ((a b) ($<= a b))
   (rest
    (comparer (lambda (a b) ($<= a b)) rest))))
(define >=
  (case-lambda
   ((a b) ($>= a b))
   (rest
    (comparer (lambda (a b) ($>= a b)) rest))))
(define =
  (case-lambda
   ((a b) ($= a b))
   (rest
    (comparer (lambda (a b) ($= a b)) rest))))
(define (not a) (if a #f #t))

(define (eq? a b) ($eq a b))
(define (eqv? a b) ($eqv? a b))
(define (equal? a b)
  (if (eqv? a b) #t
      (cond
       ((pair? a)
	(and (pair? b) (equal? (car a) (car b)) (equal? (cdr a) (cdr b))))
       ((string? a)
	(and (string? b) (string=? a b)))
       ((vector? a) 
	(and (vector? b)
	     (= (vector-length a) (vector-length b))
	     (let loop ((i 0))
	       (if (< i (vector-length a))
		   (if (equal? (vector-ref a i) (vector-ref b i))
		       (loop (+ i 1))
		       #f)
		   #t)))) 
       (else #f))))

(define (car a) ($car a))
(define (cdr a) ($cdr a))
(define (set-car! c a) ($set-car! c a))
(define (set-cdr! c a) ($set-cdr! c a))
(define (cons a b) ($cons a b))
(define list
  (case-lambda
    ((a) (cons a '()))
    ((a b) (cons a (cons b '())))
    ((a b c) (cons a (cons b (cons c '()))))
    (rest rest)))

(define (cddr e) (cdr (cdr e)))
(define (caar e) (car (car e)))
(define (cadr e) (car (cdr e)))
(define (cdar e) (cdr (car e)))

(define (caddr e) (car (cddr e))) 
(define (cdddr e) (cdr (cddr e))) 
(define (caaar e) (car (caar e)))
(define (cdaar e) (cdr (caar e)))
(define (caadr e) (car (cadr e)))
(define (cdadr e) (cdr (cadr e)))
(define (cadar e) (car (cdar e)))
(define (cddar e) (cdr (cdar e)))

(define (caaddr e) (car (caddr e))) 
(define (cdaddr e) (cdr (caddr e))) 
(define (cadddr e) (car (cdddr e))) 
(define (cddddr e) (cdr (cdddr e))) 
(define (caaaar e) (car (caaar e)))
(define (cdaaar e) (cdr (caaar e)))
(define (cadaar e) (car (cdaar e)))
(define (cddaar e) (cdr (cdaar e)))
(define (caaadr e) (car (caadr e)))
(define (cdaadr e) (cdr (caadr e)))
(define (cadadr e) (car (cdadr e)))
(define (cddadr e) (cdr (cdadr e)))
(define (caadar e) (car (cadar e)))
(define (cdadar e) (cdr (cadar e)))
(define (caddar e) (car (cddar e)))
(define (cdddar e) (cdr (cddar e)))

(define map
  (case-lambda
    ((f lst)
     (let loop ((f f) (lst lst))
       (if (null? lst) '()
	   (cons (f (car lst)) (loop f (cdr lst))))))
   (lst (let loop ((lsts (cons (cadr lst) (cddr lst))))
    (let ((hds (let loop2 ((lsts lsts))
		 (if (null? lsts)
		     '()
		     (let ((x (car lsts)))
		       (and (not (null? x))
			    (let ((r (loop2 (cdr lsts))))
			      (and r (cons (car x) r)))))))))
      (if hds
	  (cons
	   (apply (car lst) hds)
	   (loop
	    (let loop3 ((lsts lsts))
	      (if (null? lsts)
		  '()
		  (cons (cdr (car lsts)) (loop3 (cdr lsts)))))))
	  '()))))))

(define append
  (case-lambda
    ((a b)
     (let loop ((a a) (b b))
       (if (null? a)
	   b
	   (cons (car a) (loop (cdr a) b)))))
    ((a b c) (append a (append b c)))
    ((a b c d) (append a (append b (append c d))))
   (lsts (if (null? lsts) '()
      (let loop ((lsts lsts))
	(if (null? (cdr lsts))
	    (car lsts)
	    (let copy ((node (car lsts)))
	      (if (pair? node)
		  (cons (car node) (copy (cdr node)))
		  (loop (cdr lsts))))))))))

(define (reverse lst)
  (let loop ((lst lst) (rest '()))
    (if (pair? lst)
	(loop (cdr lst) (cons (car lst) rest))
	rest)))

(define (list-ref lst n)
  (let loop ((lst lst) (n n))
    (if (zero? n)
	(car lst)
	(loop (cdr lst) (- n 1)))))
(define (list-tail lst k)
  (let loop ((lst lst) (k k))
    (if (> k 0)
	(loop (cdr lst) (- k 1))
	lst)))

(define (assv obj1 alist1)
  (let loop ((obj obj1) (alist alist1))
    (if (null? alist) #f
	(if (eqv? (caar alist) obj) 
	    (car alist)
	    (loop obj (cdr alist))))))
(define (assq obj1 alist1)
  (let loop ((obj obj1) (alist alist1))
    (if (null? alist) #f
	(begin
	  (if (eq? (caar alist) obj) 
	      (car alist)
	      (loop obj (cdr alist)))))))
(define (assoc obj1 alist1)
  (let loop ((obj obj1) (alist alist1))
    (if (null? alist) #f
	(begin
	  (if (equal? (caar alist) obj) 
	      (car alist)
	      (loop obj (cdr alist)))))))

(define (memq obj list)
  (let loop ((list list))
    (if (null? list) #f
	(if (eq? obj (car list)) 
	    list
	    (loop (cdr list))))))
(define (memv obj list)
  (let loop ((list list))
    (if (null? list) #f
	(if (eqv? obj (car list)) 
	    list
	    (loop (cdr list))))))
(define (member obj list)
  (let loop ((list list))
    (if (null? list) #f
	(if (equal? obj (car list)) 
	    list
	    (loop (cdr list))))))

(define (zero? a) ($= a 0))

(define make-vector
  (case-lambda
   ((len) ($make-vector len #f))
   ((len val) ($make-vector len val))))
(define (vector-set! v k obj)
  ($vector-set! v k obj))
(define (vector-ref v k)
  ($vector-ref v k))
(define (vector->list v)
    (let loop ((l (- (vector-length v) 1)) 
	       (lst '()))
      (if (not (< l 0))
	    (loop (- l 1) (cons (vector-ref v l) lst))
	    lst)))
(define (vector-length v)
  ($vector-length v))
(define (string-length v)
  ($string-length v))

(define (vector-map fun vec)
  (let ((res (make-vector (vector-length vec))))
    (do ((i 0 (+ i 1)))
        ((= i (vector-length res)) res)
      (vector-set! res i (fun (vector-ref vec i))))))

(define (negative? a)
  ($< a 0))
(define (positive? a)
  (> a 0))
(define (odd? n)
  (not (even? n)))
(define (even? n)
  (= 0 (remainder n 2)))
(define (abs a)
  (if (negative? a)
      (* a -1)
      a))

(define max
  (case-lambda
   ((a b)
    (let ((res (if (> a b) a b)))
      (if (or (inexact? a) (inexact? b))
	  (inexact res) res)))
   (args (let loop ((args args))
      (if (eq? (length args) 1)
	  (car args)
	  (let* ((a (car args))
		 (b (cadr args))
		 (m (if (< a b) b a))
		 (i (if (or (inexact? a) (inexact? b)) (inexact m) m)))
	    (loop (cons i (cddr args)))))))))

(define min
  (case-lambda
   ((a b)
    (let ((res (if (< a b) a b)))
      (if (or (inexact? a) (inexact? b))
	  (inexact res) res)))
   (args
    (let loop ((args args))
      (if (eq? (length args) 1)
	  (car args)
	  (let* ((a (car args))
		 (b (cadr args))
		 (m (if (> a b) b a))
		 (i (if (or (inexact? a) (inexact? b)) (inexact m) m)))
	    (loop (cons i (cddr args)))))))))

(define (length e)
  (let length-loop ((e e) (cnt 0))
    (if (pair? e)
	(length-loop (cdr e) (+ cnt 1))
	cnt)))
(define (list->vector lst)
  (let ((v (make-vector (length lst))))
    (define (setloop place item v)
      (if (not (pair? item))
	  v
	  (begin
	    (vector-set! v place (car item))
	    (setloop (+ place 1) (cdr item) v))))
    (setloop 0 lst v)))



(define (list? x)
  (let loop ((fast x) (slow x))
    (or (null? fast)
	(and (pair? fast)
	     (let ((fast (cdr fast)))
	       (or (null? fast)
		   (and (pair? fast)
			(let ((fast (cdr fast))
			      (slow (cdr slow)))
			  (and (not (eq? fast slow))
			       (loop fast slow))))))))))

(define display
  (case-lambda
   ((arg) (display arg current-output-port-internal))
   ((arg port)
    (cond
     ((null? arg) (display "()" port))
     ((pair? arg)
      (display "(" port)
      (let loop ((arg arg))
	(if (not (pair? arg)) (begin (display ". " port) (display arg port))
	    (begin (display (car arg) port) 
		   (if (not (null? (cdr arg)))
		       (begin
			 (display " " port)
			 (loop (cdr arg)))))))
      (display ")" port))
     ((vector? arg)
      (display "#" port)
      (display (vector->list arg) port))
     (else ($write arg port))))))

(define write
  (case-lambda
   ((arg) (write arg (current-output-port)))
   ((arg port)
    (cond
     ((null? arg) (display "()" port))
     ((pair? arg)
      (display "(" port)
      (let loop ((arg arg))
	(if (not (pair? arg)) (begin (display ". " port) (write arg port))
	    (begin (write (car arg) port) 
		   (if (not (null? (cdr arg)))
		       (begin
			 (display " " port)
			 (loop (cdr arg)))))))
      (display ")" port))
     ((vector? arg)
      (display "#" port)
      (write (vector->list arg) port))
     ((char? arg)
      (cond
       ((char=? #\newline arg) (display "#\\newline" port))
       ((char=? #\tab arg) (display "#\\tab" port))
       ((char=? #\space arg) (display "#\\space" port))
       ((char=? #\return arg) (display "#\\return" port))
       (else (display "#\\" port) (display arg port))))
     ((string? arg)
      (display "\"" port) 
      (for-each 
       (lambda (chr) 
	 (cond
	  ((char=? #\" chr) (display "\\\"" port))
	  ((char=? #\\ chr) (display "\\\\" port))
	  (else (display chr port))))
       (string->list arg))
      (display "\"" port))
     (else 
      ($write arg port))))))

(define write-string
  (case-lambda
   ((str) ($write str current-output-port-internal))
   ((str port) ($write str port))))

(define for-each
  (case-lambda
    ((proc lst)
     (let loop ((proc proc) (lst lst))
       (if (not (null? lst))
	   (begin
	     (proc (car lst))
	     (loop proc (cdr lst))))))
    ((proc lst1 lst2)
     (let loop ((proc proc) (lst1 lst1) (lst2 lst2))
       (if (and  (not (null? lst1)) (not (null? lst2)))
	   (begin
	     (proc (car lst1) (car lst2))
	     (loop proc (cdr lst1) (cdr lst2))))))
   ((proc . lsts) (let loop ((lsts lsts))
       (let ((hds (let loop2 ((lsts lsts))
		    (if (null? lsts)
			'()
			(let ((x (car lsts)))
			  (and (not (null? x))
			       (let ((r (loop2 (cdr lsts))))
				 (and r (cons (car x) r)))))))))
	 (if hds (begin
		   (apply proc hds)
		   (loop
		    (let loop3 ((lsts lsts))
		      (if (null? lsts)
			  '()
			  (cons (cdr (car lsts)) (loop3 (cdr lsts)))))))))))))

(define make-string
  (case-lambda
   ((len) ($make-string len #\space))
   ((len c) ($make-string len c))))
(define (string-set! s k obj)
  ($string-set! s k obj))
(define (string-ref s k)
  ($string-ref s k))
(define (string->list str)
  (let ((n (string-length str)))
    (let loop ((i (- n 1)) (lst '()))
      (if (< i 0)
	  lst
	  (loop (- i 1) (cons (string-ref str i) lst))))))
(define (char=? a b)
  ($eq a b))

(define newline
  (case-lambda
   (() ($write #\newline current-output-port-internal))
   ((port) ($write #\newline port))))

(define apply
  (case-lambda
   ((fun args)
    (case (length args)
      ((0) (fun))
      ((1) (fun (car args)))
      ((2) (fun (car args) (cadr args)))
      ((3) (fun (car args) (cadr args) (caddr args)))
      ((4) (fun (car args) (cadr args) (caddr args) (cadddr args)))
      (else 
       ($apply fun args))))
   (lst (let* ((firstargs (reverse (cdr (reverse (cdr lst)))))
	 (args (append firstargs (car (reverse (cdr lst))))))
    (apply (car lst) args)))))

(define (strcmp eq? f a b eq lt gt)
  (let loop ((pos 0) (rema (string-length a)) (remb (string-length b)))
    (cond
     ((and (= rema 0 ) (= remb 0))  eq)
     ((= rema 0)  lt)
     ((= remb 0)  gt)
     ((eq? (string-ref a pos) (string-ref b pos))
      (loop (+ pos 1) (- rema 1) (- remb 1)))
     (else
      (f (string-ref a pos) (string-ref b pos))))))

(define (string<? a b) (strcmp char=? char<? a b #f #t #f))
(define (string>? a b) (strcmp char=? char>? a b #f #f #f))
(define (string<=? a b) (strcmp char=? char<=? a b #t #t #f))
(define (string>=? a b) (strcmp char=? char>=? a b #t #f #f))
(define (string-ci<? a b) (strcmp char-ci=? char-ci<? a b #f #t #f))
(define (string-ci>? a b) (strcmp char-ci=? char-ci>? a b #f #f #f))
(define (string-ci<=? a b) (strcmp char-ci=? char-ci<=? a b #t #t #f))
(define (string-ci>=? a b) (strcmp char-ci=? char-ci>=? a b #t #f #f))
(define (string-ci=? a b) (strcmp char-ci=? char-ci=? a b #t #f #f))
(define (string=? a b) (strcmp char=? char=? a b #t #f #f))

(define (char-alphabetic? c)
  (let ((n (char->integer c)))
    (cond ((< n #x41) #f)		; A
	  ((> n #x7a) #f)		; z
	  ((> n #x60))		; a-1
	  ((< n #x5b))		; Z+1
	  (else #f))))

(define (char-numeric? c)
  (let ((n (char->integer c)))
    (cond ((< n #x30) #f)		; 0
	  ((> n #x39) #f)		; 9
	  (else #t))))

(define (char-whitespace? c)
  (let ((n (char->integer c)))
    (or (eq? n 32) (eq? n 9) (eq? n 12) (eq? n 10) (eq? n 13))))

(define (char-upper-case? c)
  (let ((n (char->integer c)))
    (cond ((< n #x41) #f)		; A
	  ((> n #x5a) #f)		; Z
	  (else #t))))

(define (char-lower-case? c)
  (let ((n (char->integer c)))
    (cond ((< n #x61) #f)		; a
	  ((> n #x7a) #f)		; z
	  (else #t))))

(define (char-upcase c)
  (let ((n (char->integer c)))
    (if (or (< n #x61)		; a
	    (> n #x7a))		; z
	(integer->char n)
	(integer->char (- n 32)))))
(define (char-downcase c) 
  (let ((n (char->integer c)))
    (if (or (< n #x41)		; A
	    (> n #x5a))		; Z
	(integer->char n)
	(integer->char (+ n 32)))))
(define (char->integer e)
  ($char->integer e))
(define (integer->char e)
  ($integer->char e))

(define (char=? x y)
  ($eq x y))
(define (char>? x y)
  (> (char->integer x) (char->integer y)))
(define (char<? x y)
  (< (char->integer x) (char->integer y)))
(define (char>=? x y)
  (>= (char->integer x) (char->integer y)))
(define (char<=? x y)
  (<= (char->integer x) (char->integer y)))
(define (char-ci=? x y)
  (char=? (char-downcase x) (char-downcase y)))
(define (char-ci>? x y)
  (char>? (char-downcase x) (char-downcase y)))
(define (char-ci<? x y)
  (char<? (char-downcase x) (char-downcase y)))
(define (char-ci>=? x y)
  (char>=? (char-downcase x) (char-downcase y)))
(define (char-ci<=? x y)
  (char<=? (char-downcase x) (char-downcase y)))

(define (symbol->string sym)
  ($symbol->string sym))
(define (string->symbol sym)
  ($string->symbol sym))

(define (string . chars) (list->string chars))
(define (list->string chars)
  (let* ((len (length chars))
	 (c (make-string len)))
    (let loop ((i 0) (chars chars))
      (if (< i len)
	  (begin
	    (string-set! c i (car chars))
	    (loop (+ i 1) (cdr chars)))))
    c))
(define (substring str start end)
  (let ((c (make-string (- end start))))
    (let loop ((i start) (j 0))
      (if (< i end)
	  (begin
	    (string-set! c j (string-ref str i))
	    (loop (+ i 1) (+ j 1)))))
    c))
(define string-append
  (case-lambda
    ((a b)
     (let* ((totallen (+ (string-length a) (string-length b)))
	    (newstr (make-string totallen)))
       (let ((end (string-length a)))
	 (let loop ((from 0) (pos 0))
	   (if (< pos end)
	       (begin
		 (string-set! newstr pos (string-ref a from))
		 (loop (+ from 1) (+ pos 1)))))
	 (let loop ((from 0) (pos end))
	   (if (< pos totallen)
	       (begin
		 (string-set! newstr pos (string-ref b from))
		 (loop (+ from 1) (+ pos 1))))))
       newstr))
    (strs
     (let* ((totallen (apply + (map string-length strs)))
	    (newstr (make-string totallen)))
       (let loop ((strs strs) (place 0))
	 (if (not (null? strs))
	     (let ((end (+ place (string-length (car strs)))))
	       (let loop ((from 0) (pos place))
		 (if (< pos end)
		     (begin
		       (string-set! newstr pos (string-ref (car strs) from))
		       (loop (+ from 1) (+ pos 1)))))
	       (loop (cdr strs) end))))
       newstr))))

(define vector
  (case-lambda
    (() (make-vector 0))
    ((a) (let ((v (make-vector 1)))
	   (vector-set! v 0 a)
	   v))
    ((a b) (let ((v (make-vector 2)))
	   (vector-set! v 0 a)
	   (vector-set! v 1 b)
	   v))
    ((a b c) (let ((v (make-vector 3)))
	   (vector-set! v 0 a)
	   (vector-set! v 1 b)
	   (vector-set! v 2 c)
	   v))
    (rest (list->vector rest))))

(define number->string
  (case-lambda
   ((num) (number->string num 10))
   ((num base) (let* ((buflen 100)
	 (buffer (make-string buflen)))
    (cond ((inexact? num) (error "number->string dtoa")		;($dtoa num)
	   )
	  ((eq? num 0) "0")
	  (else
	   (let ((neg (negative? num)))
	     (let loop ((p buflen) (n (if neg (- 0 num) num)))
	       (cond ((eq? n 0)
		      (if neg
			  (begin
			    (set! p (- p 1))
			    (string-set! buffer p #\-)))
		      (substring buffer p buflen))
		     (else
		      (let ((q (/ n base))
			    (r (modulo n base))
			    (p (- p 1)))
			(string-set! buffer p (integer->char (+ (if (>= r 10) 87 48) r)))
			(loop p q))))))))))))

(include "str2num.scm")

(define (call-with-current-continuation l)
  (let ((cc ($callcc 0)))
    (l (lambda (res) ($callcc-resume cc res)))))

(define current-input-port-internal ($open 0 #t))
(define current-output-port-internal ($open 1 #f))
(define current-error-port-internal ($open 2 #f))

(define (current-input-port) current-input-port-internal)
(define (current-output-port) current-output-port-internal)
(define (current-error-port) current-error-port-internal)

(define (with-input-from-file file thunk)
  (let ((p (open-input-file file))
	(old-port current-input-port-internal))
    (set! current-input-port-internal p)
    (let ((res (thunk)))
      (set! current-input-port-internal old-port)
      (close-input-port p)
      res)))

(define (with-output-to-file file thunk)
  (let ((p (open-output-file file))
	(old-port current-output-port-internal))
    (set! current-output-port-internal p)
    (let ((res (thunk)))
      (set! current-output-port-internal old-port)
      (close-output-port p)
      res)))
(define (input-port? port)
  ($guard port #x0019))
(define (output-port? port)
  ($guard port #x0019))

(define (open-input-file filename)
  ($open filename #t))
(define (close-input-port port)
  ($close port))
(define (open-output-file filename)
  ($open filename #f))
(define (close-output-port port)
  ($close port))

(define (call-with-input-file file l)
  (let* ((p (open-input-file file))
	 (res (l p)))
    (close-input-port p)
    res))

(define (call-with-output-file file l)
  (let* ((p (open-output-file file))
	(res (l p)))
    (close-output-port p)
    res))

(define read-char
  (case-lambda
   (() ($read current-input-port-internal))
   ((port) ($read port))))

(define peek-char
  (case-lambda
   (() ($peek current-input-port-internal))
   ((p) ($peek p))))

(define write-char
  (case-lambda
   ((c) ($write c current-output-port-internal))
   ((c port) ($write c port))))

(define (eof-object? c)
  ($guard c #x1c))

(define read
  (case-lambda
   (() (read current-input-port-internal))
   ((port)
    (define (read-error msg . args)
    (display "READ ERROR:") (display msg) (newline))
  (let ((cs #f);(case-sensitive))
	(eol (lambda (c) (read-error "unexpected delimiter" c))))
    (define (parse-token t)
      (or (string->number t)
	  (string->symbol t)))
    (define (read1)
      (let ((c (read-char port)))
	(if (eof-object? c) 
	    c
	    (case c
	      ((#\#) (read-sharp))
	      ((#\() (read-list #\)))
	      ((#\[) (read-list #\]))
	      ((#\{) (read-list #\}))
	      ((#\,)
	       (cond ((eqv? (peek-char port) #\@)
		      (read-char port)
		      (list 'unquote-splicing (read1)))
		     (else (list 'unquote (read1)))))
	      ((#\`) (list 'quasiquote (read1)))
	      ((#\') `',(read1))
	      ((#\;) (skip-line) (read1))
	      ((#\") (read-string))
	      ((#\|) (string->symbol (read-delimited #\|)))
	      ((#\) #\] #\}) (eol c))
	      (else
	       (if (char-whitespace? c)
		   (read1)
		   (parse-token (read-token (list (docase c)) cs))))))))
    (define (skip-line)
      (let ((c (read-char port)))
	(if (not (or (eof-object? c) (char=? #\newline c)))
	    (skip-line))))
    (define (skip-whitespace)		; returns peeked char
      (let ((c (peek-char port)))
	(cond ((eof-object? c) c)
	      ((char-whitespace? c)
	       (read-char port)
	       (skip-whitespace))
	      (else c))))
    (define (read-sharp)
      (let ((c (read-char port)))
	(if (eof-object? c)
	    (read-error "unexpected EOF after `#'")
	    (case c
	      ((#\f #\F) #f)
	      ((#\t #\T) #t)
	      ((#\x #\X) (string->number (read-token '() #f) 16))
	      ((#\o #\O) (string->number (read-token '() #f) 8))
	      ((#\b #\B) (string->number (read-token '() #f) 2))
	      ((#\i #\I) 
	       (let* ((tok (read-token '() #f))
		      (n (string->number tok)))
		 (if (not (number? n))
		     (read-error "invalid number syntax" tok)
		     (if (inexact? n) 
			 n
			 (exact->inexact n)))))
	      ((#\e #\E) 
	       (let* ((tok (read-token '() #f))
		      (n (string->number tok)))
		 (if (not (number? n))
		     (read-error "invalid number syntax" tok)
		     (if (exact? n) 
			 n
			 (inexact->exact n)))))
	      ;; 	      ((#\u #\U)
	      ;; 	       (let ((tok (read-token '() #f)))
	      ;; 		 (cond ((string=? tok "8")
	      ;; 			(read-char port) ; skip initial "(" (must come directly after "u8"!)
	      ;; 			(let* ((lst (read-list #\)))
	      ;; 			       (len (length lst))
	      ;; 			       (bv (%allocate-block #x12 len #f len #f #f)))
	      ;; 			  (do ((i 0 (%fx+ i 1))
	      ;; 			       (lst lst (cdr lst)))
	      ;; 			      ((%fx>=? i len))
	      ;; 			    (let ((elt (car lst)))
	      ;; 			      (unless (and (exact? elt) (%fx>=? elt 0) (%fx<? elt 256))
	      ;; 				(read-error "invalid element in bytevector" elt))
	      ;; 			      (%byte-set! bv i (car lst))))
	      ;; 			  bv))
	      ;; 		       (else
	      ;; 			(read-error "invalid read syntax" (string-append "#" (string c) tok))))))
	      ((#\() (list->vector (read-list #\))))
	      ((#\;) (read1) (read1))
	      ((#\%) (string->symbol (read-token (list (docase c) #\#) cs)))
	      ((#\!) (skip-line) (read1))
	      ((#\\) 
	       (let* ((t (read-token '() #t))
		      (len (string-length t)))
		 (cond ((string-ci=? "newline" t) #\newline)
		       ((string-ci=? "tab" t) #\tab)
		       ((string-ci=? "space" t) #\space)
		       ((string-ci=? "return" t) #\return)
		       ((eq? 0 len) (read-char port))
		       ((and (char-ci=? #\x (string-ref t 0))
			     (> len 1))
			(integer->char
			 (or (string->number (substring t 1 (string-length t)) 16)
			     (read-error "invalid character name" t))))
		       (else (string-ref t 0)))))
	      ((#\') `(syntax ,(read1))) ; for... whatever
	      (else (read-error "invalid `#' syntax" c))))))
    (define (read-list delim)
      (call-with-current-continuation
       (lambda (return)
	 (let ((lst '())
	       (old eol))
	   (set! eol
		 (lambda (c)
		   (set! eol old)
		   (if (eqv? c delim)
		       (return (reverse lst))
		       (read-error "missing closing delimiter" delim))))
	   (let loop ()
	     (let ((c (skip-whitespace)))
	       (cond ((eof-object? c)
		      (read-error "unexpected EOF while reading list"))
		     ((char=? c delim)
		      (read-char port)
		      (set! eol old)
		      (return (reverse lst)))
		     (else
		      (if (eqv? #\. c)
			  (let ((t (read-token '() cs)))
			    (if (string=? "." t)
				(let ((rest (read1)))
				  (skip-whitespace)
				  (set! eol old)
				  (if (eqv? (read-char port) delim)
				      (return (append (reverse lst) rest))
				      (read-error "missing closing delimiter" delim)))
				(set! lst (cons (parse-token t) lst))))
			  (set! lst (cons (read1) lst)))
		      (loop)))))))))
    (define (read-delimited delim)
      (let loop ((lst '()))
	(let ((c (read-char port)))
	  (cond ((eof-object? c)
		 (read-error "unexpected EOF while reading delimited token"))
		((char=? delim c) 
		 (list->string (reverse lst)))
		((char=? #\\ c)
		 (let ((c (read-char port)))
		   (if (eof-object? c)
		       (read-error "unexpected EOF while reading delimited token")
		       (case c
			 ((#\n) (loop (cons #\newline lst)))
			 ((#\a) (loop (cons (integer->char 9) lst)))
			 ((#\r) (loop (cons #\return lst)))
			 ((#\t) (loop (cons #\tab lst)))
			 ((#\x)
			  (let loop2 ((v 0) (i 0))
			    (let ((c (read-char port)))
			      (cond ((eof-object? c)
				     (read-error "unexpected EOF while reading delimited token"))
				    ((char=? #\; c) 
				     (loop (cons (integer->char v) lst)))
				    ((and (char>=? c #\0) (char<=? c #\9))
				     (loop2 (+ (arithmetic-shift v 4) (- (char->integer c) 48)) (+ i 1)))
				    ((and (char>=? c #\a) (char<=? c #\f))
				     (loop2 (+ (arithmetic-shift v 4) (- (char->integer c) 87)) (+ i 1)))
				    ((and (char>=? c #\A) (char<=? c #\F))
				     (loop2 (+ (arithmetic-shift v 4) (- (char->integer c) 55)) (+ i 1)))
				    (else (read-error "invalid escaped hexadecimal character in delimited token" c))))))
			 (else (loop (cons c lst)))))))
		(else (loop (cons c lst)))))))
    (define (read-string) (read-delimited #\"))
    (define (docase c)
      (if cs
	  c
	  (char-downcase c)))
    (define (read-token prefix cs)
      (let loop ((lst prefix))	     ; prefix must be in reverse order
	(let ((c (peek-char port)))
	  (if (or (eof-object? c)
		  (char-whitespace? c)
		  (memv c '(#\{ #\} #\( #\) #\[ #\] #\; #\")))
	      (list->string (reverse lst))
	      (let ((c (read-char port)))
		(loop (cons (if cs c (docase c)) lst)))))))
    (read1)))))

(define (force x) (x))

(define values
  (case-lambda
   ((a) a)
   ((a b) (cons a (cons b '())))
   ((a b c) (cons a (cons b (cons c '()))))
   (rest rest)))

(define (call-with-values producer consumer)
  (apply consumer (producer)))

(define (inexact x)
  ($inexact x))
(define (exact x)
  ($exact x))
(define exact->inexact inexact)
(define inexact->exact exact)

(define (file-exists? file)
  ($file-exists? file))
(define (delete-file file)
  ($delete-file file))
(define read-line
  (case-lambda
   (() ($read-line current-input-port-internal))
   ((port) ($read-line port))))

;;; Include the bytecode compiler
(include "bc.scm")

(define (exact-integer-sqrt s)
  (if (<= s 1)
      s
      (let* ((x0 (quotient s 2))
	     (x1 (quotient (+ x0 (quotient s x0)) 2)))
	(let loop ((x0 x0) (x1 x1))
	  (if (< x1 x0)
	      (loop x1 (quotient (+ x1 (quotient s x1)) 2))
	      x0)))))

(define (write-double d port) ($write-double d port))
(define (round num) ($round num))
(define (sin num) ($sin num))
(define (sqrt num) ($sqrt num))
(define (atan num) ($atan num))
(define (cos num) ($cos num))
(define (truncate num) ($truncate num))
(define (floor num) ($floor num))
(define (ceiling num) ($ceiling num))
(define (exp num) ($exp num))
(define (log num) ($log num))
(define (tan num) ($tan num))
(define (asin num) ($asin num))
(define (acos num) ($acos num))
;;;;;;;; Junk for testing benchmarks ;;;;;;;
(define (pp arg) (display arg) (newline))
(define println pp)
(define pretty-print display)

(define print display)

(define (atom? a) (not (pair? a)))
(define write-u8
  (case-lambda
   ((c) ($write-u8 c current-output-port-internal))
   ((c port) ($write-u8 c port))))
(define (flush-output-port p) 0)

