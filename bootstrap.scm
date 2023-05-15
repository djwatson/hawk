;;These have to match memory_layout.scm and types.h.
(define (number? x) (or (fixnum? x) (flonum? x)))
(define (flonum? x) ($guard x 2))
(define (fixnum? x) ($guard x 0))
(define (null? x) ($guard x 23))
(define (boolean? x) ($guard x 7))
(define (char? x) ($guard x #b00001111))
(define (pair? x) ($guard x 3))
(define (procedure? x) ($guard x 5))
(define (symbol? x) ($guard x 4))
(define (vector? x) ($guard x 17))
(define (string? x) ($guard x 9))
(define (port? x) ($guard x #b011001))
(define (+ a b) ($+ a b))
(define (- a b) ($- a b))
(define (* a b) ($* a b))
(define (< a b) ($< a b))
(define (= a b) ($= a b))
(define (not a) (if a #f #t))
(define (> a b) (not (or ($= a b) ($< a b))))

(define (eq? a b) ($eq a b))
(define (eqv? a b)
  (or ($eq a b)
      (and (flonum? a) (flonum? b)
	   ($= a b))))
(define (equal? a b)
  (if (eqv? a b) #t
      (cond
       ((pair? a)
	(and (pair? b) (equal? (car a) (car b)) (equal? (cdr a) (cdr b))))
       ((string? a)
	(and (string? b) (string=? a b)))
       ((vector? a) ; TODO make faster
	(and (vector? b) (equal? (vector->list a) (vector->list b)))) 
       (else #f))))

(define (car a) ($car a))
(define (cdr a) ($cdr a))
(define (cons a b) ($cons a b))
(define (list . x) x)

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

(define (map f lst)
  (if (null? lst) '()
      (cons (f (car lst)) (map f (cdr lst)))))

(define (append a b)
  (if (null? a)
      b
      (cons (car a) (append (cdr a) b))))

(define (assv obj1 alist1)
  (let loop ((obj obj1) (alist alist1))
  (if (null? alist) #f
      (if (eqv? (caar alist) obj) 
	  (car alist)
	  (loop obj (cdr alist))))))


(define (memq obj list) 
  (if (null? list) #f
      (if (eq? obj (car list)) 
	  list
	  (memq obj (cdr list)))))

(define (zero? a) ($= a 0))

(define (make-vector len . val)
  ($make-vector len (if (pair? val) (car val) #f)))
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

(define (negative? a)
  ($< a 0))
(define (abs a)
  (if (negative? a)
      (* a -1)
      a))




(define (length e)
  (let length-loop ((e e) (cnt 0))
    (if (pair? e)
	(length-loop (cdr e) (+ 1 cnt))
	cnt)))
(define (list->vector lst)
  (define v (make-vector (length lst)))
  (define (setloop place item v)
    (if (not (pair? item))
	v
	(begin
	  (vector-set! v place (car item))
	  (setloop (+ 1 place) (cdr item) v))))
  (setloop 0 lst v)
  )



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


(define (display arg)
  (cond
   ((null? arg) (display "()" ))
   ((pair? arg)
    (display "(" )
    (let loop ((arg arg))
      (if (not (pair? arg)) (begin (display ". " ) (display arg ))
	  (begin (display (car arg) ) 
		 (if (not (null? (cdr arg)))
		     (begin
		       (display " " )
		       (loop (cdr arg)))))))
    (display ")" ))
   ((vector? arg)
    (display "#" )
    (display (vector->list arg) ))
   (else ($display arg ))))

(define (write arg)
  (cond
   ((null? arg) (display "()" ))
   ((pair? arg)
    (display "(" )
    (let loop ((arg arg))
      (if (not (pair? arg)) (begin (display ". " ) (write arg ))
	  (begin (write (car arg) ) 
		 (if (not (null? (cdr arg)))
		     (begin
		       (display " " )
		       (loop (cdr arg)))))))
    (display ")" ))
   ((vector? arg)
    (display "#" )
    (write (vector->list arg) ))
   ((char? arg)
    (cond
     ((char=? #\newline arg) (display "#\\newline" ))
     ((char=? #\tab arg) (display "#\\tab" ))
     ((char=? #\space arg) (display "#\\space" ))
     ((char=? #\return arg) (display "#\\return" ))
     (else (display "#\\" ) (display arg ))))
   ((string? arg)
    (display "\"" ) 
    (for-each 
     (lambda (chr) 
       (cond
	((char=? #\" chr) (display "\\\"" ))
	((char=? #\\ chr) (display "\\\\" ))
	(else (display chr ))))
     (string->list arg))
    (display "\"" ))
   (else 
    ($display arg))))

(define (for-each proc lst )
  (if (not (null? lst))
      (begin
	(proc (car lst))
	(for-each proc (cdr lst)))))

(define (for-each3 proc lst1 lst2)
  (if (and  (not (null? lst1)) (not (null? lst2)))
      (begin
	(proc (car lst1) (car lst2))
	(for-each3 proc (cdr lst1) (cdr lst2)))))

(define (make-string len . val)
  ($make-string len (if (pair? val) (car val) #\space)))
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

(define (newline)
  (display #\newline))

(define (apply fun args)
  ($apply fun args))

;;;;;;;;;;;;;;;;
(define cur-section '())(define errs '())
(define SECTION (lambda args
		  (display "SECTION") (write args) (newline)
		  (set! cur-section args) #t))
(define record-error (lambda (e) (set! errs (cons (list cur-section e) errs))))

(define test
  (lambda (expect fun . args)
    (write (cons fun args))
    (display "  ==> ")
    ((lambda (res)
      (write res)
      (newline)
      (cond ((not (equal? expect res))
	     (record-error (list res expect (cons fun args)))
	     (display " BUT EXPECTED ")
	     (write expect)
	     (newline)
	     #f)
	    (else #t)))
     (if (procedure? fun) (apply fun args) (car args)))))
(define (report-errs)
  (newline)
  (if (null? errs) (display "Passed all tests")
      (begin
	(display "errors were:")
	(newline)
	(display "(SECTION (got expected (call)))")
	(newline)
	(for-each (lambda (l) (write l) (newline))
		  errs)))
  (newline))

(SECTION 2 1);; test that all symbol characters are supported.
'(+ - ... !.. $.+ %.- &.!  /:. :+. <-. =. >. ?. ~. _. ^.)

(SECTION 3 4)
(define disjoint-type-functions
  (list boolean? char? null? number? pair? procedure? string? symbol? vector?))
(define type-examples
  (list
   #t #f #\a '() 9739 '(test) record-error "test" "" 'test '#() '#(a b c) ))
(define i 1)
(for-each (lambda (x) (display (make-string i #\ ))
		  (set! i (+ 3 i))
		  (write x)
		  (newline))
	  disjoint-type-functions)
(define type-matrix
  (map (lambda (x)
	 (let ((t (map (lambda (f) (f x)) disjoint-type-functions)))
	   (write t)
	   (write x)
	   (newline)
	   t))
       type-examples))
(set! i 0)
(define j 0)
(for-each3 (lambda (x y)
	    (set! j (+ 1 j))
	    (set! i 0)
	    (for-each (lambda (f)
			(set! i (+ 1 i))
			(cond ((and (= i j))
			       (cond ((not (f x)) (test #t f x))))
			      ((f x) (test #f f x)))
			(cond ((and (= i j))
			       (cond ((not (f y)) (test #t f y))))
			      ((f y) (test #f f y))))
		      disjoint-type-functions))
	  (list #t #\a '() 9739 '(test) record-error "test" 'car '#(a b c))
	  (list #f #\newline '() -3252 '(t . t) car "" 'nil '#()))


(SECTION 4 1 2)
(test '(quote a) 'quote (quote 'a))
(test '(quote a) 'quote ''a)
(SECTION 4 1 3)
(test 12 (if #f + *) 3 4)
(SECTION 4 1 4)
(test 8 (lambda (x) (+ x x)) 4)
(define reverse-subtract
  (lambda (x y) (- y x)))
(test 3 reverse-subtract 7 10)
(define add4
  (let ((x 4))
    (lambda (y) (+ x y))))
(test 10 add4 6)
(test '(3 4 5 6) (lambda x x) 3 4 5 6)
(test '(5 6) (lambda (x y . z) z) 3 4 5 6)

(report-errs)
