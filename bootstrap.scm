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


