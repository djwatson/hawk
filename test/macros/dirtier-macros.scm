;(module aaa)
; How to write dirty R5RS macros
; http://groups.google.com/groups?selm=87oflzcdwt.fsf%40radish.petrofsky.org
; How to write seemingly unhygienic macros using syntax-rules 
; Date: 2001-11-19 01:23:33 PST 

; Extract a colored identifier from a form
;    extract SYMB BODY CONT
; BODY is a form that may contain an occurence of an identifier that
; refers to the same binding occurrence as SYMB, perhaps with a different
; color. CONT is a form of the shape (K-HEAD K-IDL . K-ARGS)
; where K-IDL are K-ARGS are S-expressions representing lists or the
; empty list.
; The extract macro expands into
;   (K-HEAD (extr-id . K-IDL) . K-ARGS)
; where extr-id is the extracted colored identifier. If symbol SYMB does
; not occur in BODY at all, extr-id is identical to SYMB.


(define-syntax extract
  (syntax-rules ()
    ((_ symb body _cont)
      (letrec-syntax
	((tr
           (syntax-rules (symb)
	      ((_ x symb tail (cont-head symb-l . cont-args))
	       (cont-head (x . symb-l) . cont-args)) ; symb has occurred
	      ((_ d (x . y) tail cont)   ; if body is a composite form,
	       (tr x x (y . tail) cont)) ; look inside
	      ((_ d1 d2 () (cont-head  symb-l . cont-args))
	       (cont-head (symb . symb-l) . cont-args)) ; symb does not occur
	      ((_ d1 d2 (x . y) cont)
	       (tr x x y cont)))))
	(tr body body () _cont)))))


; Extract several colored identifiers from a form
;    extract* SYMB-L BODY CONT
; where SYMB-L is the list of symbols to extract, and BODY and CONT
; has the same meaning as in extract, see above.
; 
; The extract* macro expands into
;   (K-HEAD (extr-id-l . K-IDL) . K-ARGS)
; where extr-id-l is the list of extracted colored identifiers. The extraction
; itself is performed by the macro extract.

(define-syntax extract*
  (syntax-rules ()
    ((_ (symb) body cont)      ; only one symbol: use extract to do the job
     (extract symb body cont))
    ((_ _symbs _body _cont)
     (letrec-syntax
	 ((ex-aux		; extract symbol-by-symbol
	   (syntax-rules ()
	     ((_ found-symbs () body cont)
	      (reverse () found-symbs cont))
	     ((_ found-symbs (symb . symb-others) body cont)
	      (extract symb body
		       (ex-aux found-symbs symb-others body cont)))
	     ))
	  (reverse		; reverse the list of extracted symbols
	   (syntax-rules ()     ; to match the order of SYMB-L
	     ((_ res () (cont-head () . cont-args))
	      (cont-head res . cont-args))
	     ((_ res (x . tail) cont)
	      (reverse (x . res) tail cont)))))
       (ex-aux () _symbs _body _cont)))))

(define-syntax gbind
  (syntax-rules ()
    ((_ (bind-symbol lookup-symbol prev-lookup-symbol) ((name value))
	body ...)
     (let-syntax
	 ((lookup-symbol
	   (syntax-rules (name)
	     ((_ name) value)
	     ((_ x) (prev-lookup-symbol x)))))
       body ...))))


(define-syntax make-env
  (syntax-rules ()
    ((_ dbody)
     (letrec-syntax
	 ((do-env
	   (syntax-rules ()	; all the overloaded symbols
	     ((_ (bind-symb lookup-symb) prev-lookup-symb
		 body-of-env)
	      (letrec-syntax
		  ((xbind-symb		; Bind a symbol to a value
		    (syntax-rules ()
		      ((_ . args)
		       (gbind (bind-symbol lookup-symbol prev-lookup-symbol)
			     . args))))

		   (bind-symb         ; re-defined, infected bind
		    (syntax-rules ()
		      ((_ _binding _body)
		       (letrec-syntax 
			   ((doit
			     (syntax-rules ()
			       ((_ (mybind-symb mylookup-symb)
						myold-lookup-symb
				   binding body)
				(gbind (mybind-symb mylookup-symb
						    myold-lookup-symb)
				       binding
				    (do-env	; proliferate in the body
				     (mybind-symb mylookup-symb)
						myold-lookup-symb
				     body))))))
			 (extract* (bind-symb lookup-symb)
				   _body
				   (doit () lookup-symb _binding _body))))))
		   )

		body-of-env)))))

       (extract* (bind lookup) dbody
		 (do-env () lookup dbody))
       ))))


;(display "macro-expand-time environments")

(make-env
 (bind ((a 1)) (list (lookup a)))
)

(make-env
 (bind ((a 1)) (bind ((a 2)) (list (lookup a) (lookup a))))
)


(make-env
 (bind ((a 1))
  (bind ((b 2))
     (list (lookup a) (lookup b)
       (bind ((a 3))
	  (list (lookup a) (lookup b))))))
)

; (process-complex-id term) ==> rewritten term


(define-syntax gmbind
  (syntax-rules ()
    ((_ (bind-symbol lookup-symbol prev-lookup-symbol) ((names value))
	body ...)
     (let-syntax
	 ((lookup-symbol
	   (syntax-rules names
	     ((_ . names) value)
	     ((_ . x) (prev-lookup-symbol . x)))))
       body ...))))

(define-syntax glambda
  (syntax-rules ()
    ((_ (bind-symbol lookup-symbol) ((_id ida ...)) body)
     (lambda (temp)
       (bind-symbol (((ida ...) temp)) body)))))


(define-syntax gquote
  (syntax-rules ()
    ((_ (lookup-symbol) term)
     (let-syntax
	 ((check
	   (syntax-rules (lookup-symbol)
	     ((_ (lookup-symbol . args))
	      (map symbol->string 'args))
	     ((_ x) 'x))))
       (check term)))))

	   
	  
(define-syntax make-env1
  (syntax-rules ()
    ((_ dbody)
     (letrec-syntax
	 ((do-env
	   (syntax-rules ()	; all the overloaded symbols
	     ((_ (bind-symb lookup-symb lambda-symb quote-symb)
		 prev-lookup-symb
		 body-of-env)
	      (letrec-syntax
		  ((lambda-symb	; Bind a symbol to a value
		    (syntax-rules ()
		      ((_ . args)
		       (glambda (bind-symb lookup-symb)
			     . args))))

		   (quote-symb	
		    (syntax-rules ()
		      ((_ . args)
		       (gquote (lookup-symb)
			     . args))))

		   (bind-symb         ; re-defined, infected bind
		    (syntax-rules ()
		      ((_ _binding _body)
		       (letrec-syntax 
			   ((doit
			     (syntax-rules ()
			       ((_ (mybind-symb mylookup-symb
				    mylambda-symb myquote-symb)
						myold-lookup-symb
				   binding body)
				(gmbind (mybind-symb mylookup-symb
						    myold-lookup-symb)
				       binding
				    (do-env	; proliferate in the body
				     (mybind-symb mylookup-symb
						  mylambda-symb myquote-symb)
						myold-lookup-symb
				     body))))))
			 (extract* (bind-symb lookup-symb
					      lambda-symb quote-symb)
				   _body
				   (doit () lookup-symb _binding _body))))))
		   )

		body-of-env)))))

       (extract* (bind id lambda quote) dbody
		 (do-env () lookup dbody))
       ))))

; (make-env1
;  (bind (((a b c) 1)) (list (lookup a b c)))
; )

(make-env1
 (lambda ((id a b c)) (id a b c))
)

(make-env1
 (lambda ((id a b c)) (lambda ((id a b)) (list (id a b c) (id a b))))
)

(make-env1
 (lambda ((id a b c)) (lambda ((id a b)) 
			(list (id a b c) (id a b) '(id a b x) '(id a b) 'x)
			))
					       
)

; (concat-ids (id a b c) (id x y z)) => (id a b c x y z)
; For now assume that a, b, c, x, y, z are all distinct symbols

(define-syntax concat-ids
  (syntax-rules (id)
    ((_ (a ...) (x ...)) (id a ... x ...))))

(make-env1
 (let-syntax
     ((add-c
       (syntax-rules ()
	 ((_ id a b) (id a b c)))))
 (lambda ((id a b c))
   (lambda ((id a b))
     (lambda ((id c))
       (list (id a b) (id c) (add-c id a b)))))
))

(define result (((
(make-env1
 (let-syntax
     ((add-c
       (syntax-rules ()
	 ((_ id a b) (id a b c)))))
 (lambda ((id a b c))
   (lambda ((id a b))
     (lambda ((id c))
       (list (id a b) (id c) (add-c id a b)))))
))
1) 2) 3))

