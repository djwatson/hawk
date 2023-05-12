;; Map including improper
(define (imap f l)
  (if (null? l) 
      '()
      (if (atom? l)
	  (f l)
	  (cons (f (car l)) (imap f (cdr l))))))

(define (improper? l)
  (if (null? l) #f
      (if (atom? l) #t
	  (improper? (cdr l)))))

;;(define (atom? e) (not (pair? e)))

;; Change ((lambda ..) ...) to
;; (let (...) ...)
(define (optimize-direct c)
  (define (sexp-direct f)
    (define params (second (first f)))
    (define args (cdr f))
    (define body (cddr (first f)))
    (sexp `(let ,(map list params args) ,@body)))
  (define (sexp f)
    (if (not (pair? f))
	f
	(case (car f)
	  ((quote) f)
	  (else
	   (if (and (pair? (car f)) (eq? 'lambda (caar f)))
	       (sexp-direct f)
	       (imap sexp f))))))
  (imap sexp c))

(define (union a b) (lset-union eq? a b))
(define (assignment-conversion c)
  (define (find-assigned f)
    (if (atom? f)
	'()
	(case (car f)
	  ((set!) (list (second f)))
	  ((quote) '())
	  (else (fold union '() (imap find-assigned f))))))
  (define assigned (find-assigned c))
  (display (format "Assigned: ~a\n" assigned))
  c)
