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

(define (caar a) ($car ($car a)))
(define (car a) ($car a))
(define (cdr a) ($cdr a))
(define (cadr a) ($car ($cdr a)))
(define (cons a b) ($cons a b))
(define (list . x) x)

(define (map . lst)
  (let loop ((lsts (cons (cadr lst) (cddr lst))))
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
	  '())))  )

;; (define (append . lsts)
;;   (if (null? lsts) '()
;;       (let loop ((lsts lsts))
;; 	(if (null? (cdr lsts))
;; 	    (car lsts)
;; 	    (let copy ((node (car lsts)))
;; 	      (if (pair? node)
;; 		  (cons (car node) (copy (cdr node)))
;; 		  (loop (cdr lsts))))))))

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
(define (negative? a)
  ($< a 0))



`(a ,(+ 1 2) ,@(map abs '(4 -5 6)) b)
