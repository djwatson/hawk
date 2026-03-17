(import (only (scheme base)
              or
	      and
              define
	      unless
	      cond
              let
              let*
              if
              >
              <
              >=
              <=
              =
              begin
              quote
              do
              when
	      else
	      )
	(scheme case-lambda)
		(only (scheme write) display) (prefix (hawk sys) sys:))
(define (write x) (display x))
(define (newline) (display "\n"))

(define (* a b) (sys:MUL a b))
(define (+ a b) (sys:ADD a b))
(define (- a b) (sys:SUB a b))
(define (/ a b) (sys:DIV a b))
(define (eq? a b) (sys:EQ a b))

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

(define for-each
  (case-lambda
   ((proc lst)
					;(unless (list? lst) (error "circular for-each"))
    (let loop ((proc proc) (lst lst))
      (unless (null? lst)
	(proc (car lst))
	(loop proc (cdr lst)))))
   ((proc lst1 lst2)
					;(unless (or (list? lst1) (list? lst2)) (error "circular for-each"))
    (let loop ((proc proc) (lst1 lst1) (lst2 lst2))
      (if (and  (not (null? lst1)) (not (null? lst2)))
	  (begin
	    (proc (car lst1) (car lst2))
	    (loop proc (cdr lst1) (cdr lst2))))))
   ((proc . lsts)
					;(unless (any list? lsts) (error "circular for-each"))
    (display "ABORT apply unimplemend")
    (/ 1 0)
    ;; (let loop ((lsts lsts))
    ;;   (let ((hds (let loop2 ((lsts lsts))
    ;; 		   (if (null? lsts)
    ;; 		       '()
    ;; 		       (let ((x (car lsts)))
    ;; 			 (and (not (null? x))
    ;; 			      (let ((r (loop2 (cdr lsts))))
    ;; 				(and r (cons (car x) r)))))))))
    ;; 	(if hds (begin
    ;; 		  (apply proc hds)
    ;; 		  (loop
    ;; 		   (let loop3 ((lsts lsts))
    ;; 		     (if (null? lsts)
    ;; 			 '()
    ;; 			 (cons (cdr (car lsts)) (loop3 (cdr lsts))))))))))
    )))

(define (eqv? a b)
  (or (eq? a b) (and (flonum? a) (flonum? b) (= a b))))
(define (equal? a b)
  (cond
   ((eqv? a b) #t)
   ((and (null? a) (null? b)) #t)
   ((and (string? a) (string? b)) (string=? a b))
   ((and (bytevector? a) (bytevector? b)) (bytevector=? a b))
   ((and (symbol? a) (symbol? b)) (string=? (symbol->string a) (symbol->string b)))
   ((and (vector? a) (vector? b)) (equal? (vector->list a) (vector->list b)))
   ((and (pair? a) (pair? b)
	 (equal? (car a) (car b))
	 (equal? (cdr a) (cdr b))) #t)
   (else #f)))

(define (string-ref str idx) (sys:LOAD_CHAR str idx))
(define (string-set! str idx c) (sys:STORE_CHAR str c idx))
(define (string=? a b)
  (let ((len-a (sys:LOAD a 0)) (len-b (sys:LOAD b 0)))
    (and (= len-a len-b)
         (let loop ((i 0))
           (if (= i len-a)
               #t
               (and (= (string-ref a i) (string-ref b i))
                    (loop (+ i 1))))))))
(define make-string
  (case-lambda
   ((len) (make-string len #f))
   ((len c)
    (let* ((size (+ len 17))
           (alloc_size
            (let loop ((n 8))
              (if (>= n size) n (loop (+ n 8)))))
           (str (sys:ALLOC alloc_size 9)))
    (sys:STORE str len 0)
    (string-set! str len #\x00)
    (when c
      (do ((i 0 (+ i 1)))
	  ((= i len))
	(string-set! str i c)))
    str))))

(define (cons a b)
  (let ((cell (sys:ALLOC 24 3))) (sys:STORE cell a 0) (sys:STORE cell b 1) cell))
(define (not a) (if a #f #t))
(define (null? a) (sys:GUARD a 20))
(define (pair? a) (sys:GUARD a 3))
(define (boolean? a) (sys:GUARD a 4))
(define (char? a) (sys:GUARD a 12))
(define (fixnum? a) (sys:GUARD a 0))
(define (flonum? a) (sys:GUARD a 2))
(define (number? x)
  (or (fixnum? x)
     (flonum? x) ;(bignum? x) (ratnum? x) (compnum? x)
  ))
(define (bytevector=? a b) #f)
(define (procedure? a) (sys:GUARD a 5))
(define (string? a) (sys:GUARD a 9))
(define (bytevector? a) (sys:GUARD a #x39))
(define (symbol? a) (sys:GUARD a 6))
(define (symbol->string sym) (sys:LOAD sym 0))
(define (vector? a) (sys:GUARD a 7))
(define (zero? z) (= z 0))
(define (negative? a) (< a 0))
(define (positive? a) (> a 0))
(define (list-tail lst k)
  (let loop ((lst lst) (k k)) (if (> k 0) (loop (cdr lst) (- k 1)) lst)))
(define (list . x) x)
(define (cdr a) (sys:LOAD a 1))
(define (car a) (sys:LOAD a 0))
(define (set-car! a b) (sys:STORE a b 0))
(define (set-cdr! a b) (sys:STORE a b 1))
(define (car a) (sys:LOAD a 0))
(define (cadr a) (car (cdr a)))
(define (caar a) (car (car a)))
(define (caddr a) (car (cdr (cdr a))))
(define (cddr a) (cdr (cdr a)))
(define (map f a) (if (null? a) '() (cons (f (car a)) (map f (cdr a)))))
(define (append2 a b)
  (let loop ((a a) (b b))
    (if (null? a)
	b
	(cons (car a) (loop (cdr a) b)))))

(define append
  (case-lambda
    ((a b)
     (append2 a b))
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
  (let loop ((lst lst) (res '()))
    (if (pair? lst)
	(loop (cdr lst) (cons (car lst) res))
	res)))
(define (list-ref lst n)
  (let loop ((lst lst) (n n))
    (if (zero? n)
	(car lst)
	(loop (cdr lst) (- n 1)))))
(define (vector-length vec) (sys:LOAD vec 0))
;; Be careful here, we need to initialize vec before ANY other allocations
;; (including closures)
(define (vector-init vec init pos left)
  (if (= left 0)
      vec
      (begin (vector-set! vec pos init) (vector-init vec init (+ pos 1) (- left 1)))))
(define make-vector
  (case-lambda
    ((len) (make-vector len 0))
    ((len init)
      (let ((vec (sys:ALLOC (+ 16 (sys:MUL len 8)) 7)))
        (sys:STORE vec len 0)
        (vector-init vec init 0 len)))))
(define (vector-ref vec idx) (sys:LOAD vec (+ 1 idx)))
(define (vector-set! vec idx val) (sys:STORE vec val (+ 1 idx)))
(define (length a)
  (let loop ((a a) (num 0)) (if (pair? a) (loop (cdr a) (+ num 1)) num)))
(define (vector->list vec)
  (let loop ((i (vector-length vec)) (l '()))
    (if (= i 0) l (loop (- i 1) (cons (vector-ref vec (- i 1)) l)))))
(define (list->vector lst)
  (let* ((len (length lst)) (v (make-vector len 0)))
    (do ((i 0 (+ i 1)) (p lst (cdr p))) ((= i len) v) (vector-set! v i (car p)))))

;; SIN
(define two-pi 6.28319)
(define pi (/ two-pi 2.0))
(define neg-pi (sys:MUL -1.0 pi))
(define half-pi (/ pi 2.0))
(define neg-half-pi (sys:MUL -1.0 half-pi))

(define (sin-poly x)
  ;; 9th-order odd polynomial around 0:
  ;; x - x^3/6 + x^5/120 - x^7/5040 + x^9/362880
  (let* ((x2 (sys:MUL x x)) (x3 (sys:MUL x2 x)) (x5 (sys:MUL x3 x2)) (x7 (sys:MUL x5 x2)) (x9 (sys:MUL x7 x2)))
    (+ x
       (+ (sys:MUL -0.166667 x3)
          (+ (sys:MUL 0.00833333 x5) (+ (sys:MUL -0.000198413 x7) (sys:MUL 2.75573e-06 x9)))))))

(define (reduce-angle y)
  (if (> y pi)
      (reduce-angle (- y two-pi))
      (if (< y neg-pi) (reduce-angle (+ y two-pi)) y)))
(define (sin x)
  (let ((y (reduce-angle x)))
    (if (> y half-pi)
        (sin-poly (- pi y))
        (if (< y neg-half-pi) (sys:MUL -1.0 (sin-poly (+ pi y))) (sin-poly y)))))

(define (apply fun args)
  (sys:APPLY fun args))

(define (assq obj1 alist1)
  (let loop ((obj obj1) (alist alist1))
    (if (null? alist) #f
	(begin
	  (if (eq? (caar alist) obj) 
	      (car alist)
	      (loop obj (cdr alist)))))))
(define (assv obj1 alist1)
  (let loop ((obj obj1) (alist alist1))
    (if (null? alist) #f
	(begin
	  (if (eqv? (caar alist) obj) 
	      (car alist)
	      (loop obj (cdr alist)))))))
(define assoc 
  (case-lambda
    ((obj1 alist1 compare)
     (let loop ((obj obj1) (alist alist1))
       (if (null? alist) #f
	   (begin
	     (if (compare (caar alist) obj) 
		 (car alist)
		 (loop obj (cdr alist)))))))
    ((obj alist)
     (assoc obj alist equal?))))

(define (memv obj list)
  (let loop ((list list))
    (if (null? list) #f
	(if (eq? obj (car list)) 
	    list
	    (loop (cdr list))))))
(define (memq obj list)
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
