;MzScheme version of
;schelog.scm
;Schelog
;An embedding of Prolog in Scheme
;Dorai Sitaram
;1989, revised Feb. 1993, Mar. 1997

;logic variables and their manipulation

(define schelog:*ref* "ref")

(define schelog:*unbound* '_)

(define schelog:make-ref
  ;;makes a fresh unbound ref;
  ;;unbound refs point to themselves
  (lambda opt
    (vector schelog:*ref*
      (if (null? opt) schelog:*unbound*
	(car opt)))))

(define _ schelog:make-ref)

(define schelog:ref?
  (lambda (r)
    (and (vector? r)
	 (eq? (vector-ref r 0) schelog:*ref*))))

(define schelog:deref
  (lambda (r)
    (vector-ref r 1)))

(define schelog:set-ref!
  (lambda (r v)
    (vector-set! r 1 v)))

(define schelog:unbound-ref?
  (lambda (r)
    (eq? (schelog:deref r) schelog:*unbound*)))

(define schelog:unbind-ref!
  (lambda (r)
    (schelog:set-ref! r schelog:*unbound*)))

;frozen logic vars

(define schelog:*frozen* "frozen")

(define schelog:freeze-ref
  (lambda (r)
    (schelog:make-ref (vector schelog:*frozen* r))))

(define schelog:thaw-frozen-ref
  (lambda (r)
    (vector-ref (schelog:deref r) 1)))

(define schelog:frozen-ref?
  (lambda (r)
    (let ((r2 (schelog:deref r)))
      (and (vector? r2)
	   (eq? (vector-ref r2 0) schelog:*frozen*)))))

;deref a structure completely (except the frozen ones, i.e.)

(define schelog:deref*
  (lambda (s)
    (cond ((schelog:ref? s)
	   (if (schelog:frozen-ref? s) s
	     (schelog:deref* (schelog:deref s))))
	  ((pair? s) (cons (schelog:deref* (car s))
                       (schelog:deref* (cdr s))))
	  ((vector? s)
	   (list->vector (map schelog:deref* (vector->list s))))
	  (else s))))

;%let introduces new logic variables

(define-syntax %let
  (syntax-rules ()
    ((%let (x ...) . e)
      (let ((x (schelog:make-ref)) ...)
        . e))))

;the unify predicate

(define *schelog-use-occurs-check?* #f)

(define schelog:occurs-in? 
  (lambda (var term)
    (and *schelog-use-occurs-check?*
         (let loop ((term term))
           (cond ((eqv? var term) #t)
                 ((schelog:ref? term)
                  (cond ((schelog:unbound-ref? term) #f)
                        ((schelog:frozen-ref? term) #f)
                        (else (loop (schelog:deref term)))))
                 ((pair? term)
                  (or (loop (car term)) (loop (cdr term))))
                 ((vector? term)
                  (loop (vector->list term)))
                 (else #f))))))

(define schelog:unify
  (lambda (t1 t2)
    (lambda (fk)
      (letrec
        ((cleanup-n-fail
           (lambda (s)
             (for-each schelog:unbind-ref! s)
             (fk 'fail)))
         (unify1
           (lambda (t1 t2 s)
             ;(printf "unify1 ~s ~s~%" t1 t2)
             (cond ((eqv? t1 t2) s)
                   ((schelog:ref? t1)
                    (cond ((schelog:unbound-ref? t1)
                           (cond ((schelog:occurs-in? t1 t2)
                                  (cleanup-n-fail s))
                                 (else 
                                   (schelog:set-ref! t1 t2)
                                   (cons t1 s))))
                          ((schelog:frozen-ref? t1)
                           (cond ((schelog:ref? t2)
                                  (cond ((schelog:unbound-ref? t2)
                                         ;(printf "t2 is unbound~%")
                                         (unify1 t2 t1 s))
                                        ((schelog:frozen-ref? t2)
                                         (cleanup-n-fail s))
                                        (else
                                          (unify1 t1 (schelog:deref t2) s))))
                                 (else (cleanup-n-fail s))))
                          (else 
                            ;(printf "derefing t1~%") 
                            (unify1 (schelog:deref t1) t2 s))))
                   ((schelog:ref? t2) (unify1 t2 t1 s))
                   ((and (pair? t1) (pair? t2))
                    (unify1 (cdr t1) (cdr t2)
                            (unify1 (car t1) (car t2) s)))
                   ((and (string? t1) (string? t2))
                    (if (string=? t1 t2) s
                        (cleanup-n-fail s)))
                   ((and (vector? t1) (vector? t2))
                    (unify1 (vector->list t1)
                            (vector->list t2) s))
                   (else
                     (for-each schelog:unbind-ref! s)
                     (fk 'fail))))))
        (let ((s (unify1 t1 t2 '())))
          (lambda (d)
            (cleanup-n-fail s)))))))

(define %= schelog:unify)

;disjunction

(define-syntax %or
  (syntax-rules ()
    ((%or g ...)
     (lambda (__fk)
       (call-with-current-continuation
	 (lambda (__sk)
	   (call-with-current-continuation
	     (lambda (__fk)
	       (__sk ((schelog:deref* g) __fk))))
	   ...
	   (__fk 'fail)))))))

;conjunction

(define-syntax %and
  (syntax-rules ()
    ((%and g ...)
     (lambda (__fk)
       (let* ((__fk ((schelog:deref* g) __fk))
	      ...)
	 __fk)))))

;cut

(define-syntax %cut-delimiter
  (syntax-rules (!)
    ((%cut-delimiter g)
     (lambda (__fk)
       (let ((! (lambda (__fk2) __fk)))
	 ((schelog:deref* g) __fk))))))

;Prolog-like sugar

(define-syntax %rel
  (syntax-rules (!)
    ((%rel (v ...) ((a ...) subgoal ...) ...)
      (lambda __fmls
        (lambda (__fk)
          (call-with-current-continuation
            (lambda (__sk)
              (let ((! (lambda (fk1) __fk)))
                (%let (v ...)
                  (call-with-current-continuation
                    (lambda (__fk)
                      (let* ((__fk ((%= __fmls (list a ...)) __fk))
                              (__fk ((schelog:deref* subgoal) __fk))
                              ...)
                        (__sk __fk))))
                  ...
                  (__fk 'fail))))))))))

;the fail and true preds

(define %fail
  (lambda (fk) (fk 'fail)))

(define %true
  (lambda (fk) fk))

;for structures ("functors"), use Scheme's list and vector
;functions and anything that's built using them.

;arithmetic

(define-syntax %is
  (syntax-rules (quote)
    ((%is v e)
     (lambda (__fk)
       ((%= v (%is (1) e __fk)) __fk)))

    ((%is (1) (quote x) fk) (quote x))
    ((%is (1) (x ...) fk)
     ((%is (1) x fk) ...))
    ((%is (1) x fk)
     (if (and (schelog:ref? x) (schelog:unbound-ref? x))
	 (fk 'fail) (schelog:deref* x)))))

;defining arithmetic comparison operators

(define schelog:make-binary-arithmetic-relation
  (lambda (f)
    (lambda (x y)
      (%is #t (f x y)))))

(define %=:= (schelog:make-binary-arithmetic-relation =))
(define %> (schelog:make-binary-arithmetic-relation >))
(define %>= (schelog:make-binary-arithmetic-relation >=))
(define %< (schelog:make-binary-arithmetic-relation <))
(define %<= (schelog:make-binary-arithmetic-relation <=))
(define %=/= (schelog:make-binary-arithmetic-relation
               (lambda (m n) (not (= m n)))))

;type predicates

(define schelog:constant?
  (lambda (x)
    (cond ((schelog:ref? x)
	   (cond ((schelog:unbound-ref? x) #f)
		 ((schelog:frozen-ref? x) #t)
		 (else (schelog:constant? (schelog:deref x)))))
	  ((pair? x) #f)
	  ((vector? x) #f)
	  (else #t))))

(define schelog:compound?
  (lambda (x)
    (cond ((schelog:ref? x) (cond ((schelog:unbound-ref? x) #f)
			  ((schelog:frozen-ref? x) #f)
			  (else (schelog:compound? (schelog:deref x)))))
	  ((pair? x) #t)
	  ((vector? x) #t)
	  (else #f))))

(define %constant
  (lambda (x)
    (lambda (fk)
      (if (schelog:constant? x) fk (fk 'fail)))))

(define %compound
  (lambda (x)
    (lambda (fk)
      (if (schelog:compound? x) fk (fk 'fail)))))

;metalogical type predicates

(define schelog:var?
  (lambda (x)
    (cond ((schelog:ref? x)
	   (cond ((schelog:unbound-ref? x) #t)
		 ((schelog:frozen-ref? x) #f)
		 (else (schelog:var? (schelog:deref x)))))
	  ((pair? x) (or (schelog:var? (car x)) (schelog:var? (cdr x))))
	  ((vector? x) (schelog:var? (vector->list x)))
	  (else #f))))

(define %var
  (lambda (x)
    (lambda (fk) (if (schelog:var? x) fk (fk 'fail)))))

(define %nonvar
  (lambda (x)
    (lambda (fk) (if (schelog:var? x) (fk 'fail) fk))))

; negation of unify

(define schelog:make-negation ;basically inlined cut-fail
  (lambda (p)
    (lambda args
      (lambda (fk)
	(if (call-with-current-continuation
	      (lambda (k)
		((apply p args) (lambda (d) (k #f)))))
	    (fk 'fail)
	    fk)))))

(define %/=
  (schelog:make-negation %=))

;identical

(define schelog:ident?
  (lambda (x y)
    (cond ((schelog:ref? x)
	   (cond ((schelog:unbound-ref? x)
		  (cond ((schelog:ref? y)
			 (cond ((schelog:unbound-ref? y) (eq? x y))
			       ((schelog:frozen-ref? y) #f)
			       (else (schelog:ident? x (schelog:deref y)))))
			(else #f)))
		 ((schelog:frozen-ref? x)
		  (cond ((schelog:ref? y)
			 (cond ((schelog:unbound-ref? y) #f)
			       ((schelog:frozen-ref? y) (eq? x y))
			       (else (schelog:ident? x (schelog:deref y)))))
			(else #f)))
		 (else (schelog:ident? (schelog:deref x) y))))
	  ((pair? x)
	   (cond ((schelog:ref? y)
		  (cond ((schelog:unbound-ref? y) #f)
			((schelog:frozen-ref? y) #f)
			(else (schelog:ident? x (schelog:deref y)))))
		 ((pair? y)
		  (and (schelog:ident? (car x) (car y))
		       (schelog:ident? (cdr x) (cdr y))))
		 (else #f)))
	  ((vector? x)
	   (cond ((schelog:ref? y)
		  (cond ((schelog:unbound-ref? y) #f)
			((schelog:frozen-ref? y) #f)
			(else (schelog:ident? x (schelog:deref y)))))
		 ((vector? y)
		  (schelog:ident? (vector->list x)
		    (vector->list y)))
		 (else #f)))
	  (else
	    (cond ((schelog:ref? y)
		   (cond ((schelog:unbound-ref? y) #f)
			 ((schelog:frozen-ref? y) #f)
			 (else (schelog:ident? x (schelog:deref y)))))
		  ((pair? y) #f)
		  ((vector? y) #f)
		  (else (eqv? x y)))))))

(define %==
  (lambda (x y)
    (lambda (fk) (if (schelog:ident? x y) fk (fk 'fail)))))

(define %/==
  (lambda (x y)
    (lambda (fk) (if (schelog:ident? x y) (fk 'fail) fk))))

;variables as objects

(define schelog:freeze
  (lambda (s)
    (let ((dict '()))
      (let loop ((s s))
	(cond ((schelog:ref? s)
	       (cond ((or (schelog:unbound-ref? s) (schelog:frozen-ref? s))
		      (let ((x (assq s dict)))
			(if x (cdr x)
			    (let ((y (schelog:freeze-ref s)))
			      (set! dict (cons (cons s y) dict))
			      y))))
		     ;((schelog:frozen-ref? s) s) ;?
		     (else (loop (schelog:deref s)))))
	      ((pair? s) (cons (loop (car s)) (loop (cdr s))))
	      ((vector? s)
	       (list->vector (map loop (vector->list s))))
	      (else s))))))

(define schelog:melt
  (lambda (f)
    (cond ((schelog:ref? f)
	   (cond ((schelog:unbound-ref? f) f)
		 ((schelog:frozen-ref? f) (schelog:thaw-frozen-ref f))
		 (else (schelog:melt (schelog:deref f)))))
	  ((pair? f)
	   (cons (schelog:melt (car f)) (schelog:melt (cdr f))))
	  ((vector? f)
	   (list->vector (map schelog:melt (vector->list f))))
	  (else f))))

(define schelog:melt-new
  (lambda (f)
    (let ((dict '()))
      (let loop ((f f))
	(cond ((schelog:ref? f)
	       (cond ((schelog:unbound-ref? f) f)
		     ((schelog:frozen-ref? f)
		      (let ((x (assq f dict)))
			(if x (cdr x)
			    (let ((y (schelog:make-ref)))
			      (set! dict (cons (cons f y) dict))
			      y))))
		     (else (loop (schelog:deref f)))))
	      ((pair? f) (cons (loop (car f)) (loop (cdr f))))
	      ((vector? f)
	       (list->vector (map loop (vector->list f))))
	      (else f))))))

(define schelog:copy
  (lambda (s)
    (schelog:melt-new (schelog:freeze s))))

(define %freeze
  (lambda (s f)
    (lambda (fk)
      ((%= (schelog:freeze s) f) fk))))

(define %melt
  (lambda (f s)
    (lambda (fk)
      ((%= (schelog:melt f) s) fk))))

(define %melt-new
  (lambda (f s)
    (lambda (fk)
      ((%= (schelog:melt-new f) s) fk))))

(define %copy
  (lambda (s c)
    (lambda (fk)
      ((%= (schelog:copy s) c) fk))))

;negation as failure

(define %not
  (lambda (g)
    (lambda (fk)
      (if (call-with-current-continuation
	    (lambda (k)
	      ((schelog:deref* g) (lambda (d) (k #f)))))
	  (fk 'fail) fk))))

;assert, asserta

(define %empty-rel
  (lambda args
    %fail))

(define-syntax %assert
  (syntax-rules (!)
    ((%assert rel-name (v ...) ((a ...) subgoal ...) ...)
      (set! rel-name
        (let ((__old-rel rel-name)
               (__new-addition (%rel (v ...) ((a ...) subgoal ...) ...)))
          (lambda __fmls
            (%or (apply __old-rel __fmls)
              (apply __new-addition __fmls))))))))

(define-syntax %assert-a
  (syntax-rules (!)
    ((%assert-a rel-name (v ...) ((a ...) subgoal ...) ...)
      (set! rel-name
        (let ((__old-rel rel-name)
               (__new-addition (%rel (v ...) ((a ...) subgoal ...) ...)))
          (lambda __fmls
            (%or (apply __new-addition __fmls)
              (apply __old-rel __fmls))))))))

;set predicates

(define schelog:set-cons
  (lambda (e s)
    (if (member e s) s (cons e s))))

(define-syntax %free-vars
  (syntax-rules ()
    ((%free-vars (v ...) g)
      (cons 'schelog:goal-with-free-vars
        (cons (list v ...) g)))))

(define schelog:goal-with-free-vars?
  (lambda (x)
    (and (pair? x) (eq? (car x) 'schelog:goal-with-free-vars))))

(define schelog:make-bag-of
  (lambda (kons)
    (lambda (lv goal bag)
      (let ((fvv '()))
        (when (schelog:goal-with-free-vars? goal)
          (begin (set! fvv (cadr goal))
            (set! goal (cddr goal))))
        (schelog:make-bag-of-aux kons fvv lv goal bag)))))

(define schelog:make-bag-of-aux
  (lambda (kons fvv lv goal bag)
    (lambda (fk)
      (call-with-current-continuation
        (lambda (sk)
          (let ((lv2 (cons fvv lv)))
            (let* ((acc '())
                    (fk-final
                      (lambda (d)
                        ;;(set! acc (reverse! acc))
                        (sk ((schelog:separate-bags fvv bag acc) fk))))
                    (fk-retry (goal fk-final)))
              (set! acc (kons (schelog:deref* lv2) acc))
              (fk-retry 'retry))))))))

(define schelog:separate-bags
  (lambda (fvv bag acc)
    ;;(format #t "Accum: ~s~%" acc)
    (let ((bags (let loop ((acc acc)
                            (current-fvv #f) (current-bag '())
                            (bags '()))
                  (if (null? acc)
                    (cons (cons current-fvv current-bag) bags)
                    (let ((x (car acc)))
                      (let ((x-fvv (car x)) (x-lv (cdr x)))
                        (if (or (not current-fvv) (equal? x-fvv current-fvv))
                          (loop (cdr acc) x-fvv (cons x-lv current-bag) bags)
                          (loop (cdr acc) x-fvv (list x-lv)
                            (cons (cons current-fvv current-bag) bags)))))))))
      ;;(format #t "Bags: ~a~%" bags)
      (if (null? bags) (%= bag '())
        (let ((fvv-bag (cons fvv bag)))
          (let loop ((bags bags))
            (if (null? bags) %fail
              (%or (%= fvv-bag (car bags))
                (loop (cdr bags))))))))))

(define %bag-of (schelog:make-bag-of cons))
(define %set-of (schelog:make-bag-of schelog:set-cons))

;%bag-of-1, %set-of-1 hold if there's at least one solution

(define %bag-of-1
  (lambda (x g b)
    (%and (%bag-of x g b)
      (%= b (cons (_) (_))))))

(define %set-of-1
  (lambda (x g s)
    (%and (%set-of x g s)
      (%= s (cons (_) (_))))))

;user interface

;(%which (v ...) query) returns #f if query fails and instantiations
;of v ... if query succeeds.  In the latter case, type (%more) to
;retry query for more instantiations.

(define schelog:*more-k* 'forward)
(define schelog:*more-fk* 'forward)

(define-syntax %which
  (syntax-rules (schelog:*more-k* schelog:*more-fk*)
    ((%which (v ...) g)
     (%let (v ...)
       (call-with-current-continuation
         (lambda (__qk)
           (set! schelog:*more-k* __qk)
           (set! schelog:*more-fk*
             ((schelog:deref* g)
              (lambda (d)
                (set! schelog:*more-fk* #f)
                (schelog:*more-k* #f))))
           (schelog:*more-k*
             (map (lambda (nam val) (list nam (schelog:deref* val)))
                  '(v ...)
                  (list v ...)))))))))

(define %more
  (lambda ()
    (call-with-current-continuation
      (lambda (k)
	(set! schelog:*more-k* k)
	(if schelog:*more-fk* (schelog:*more-fk* 'more)
	  #f)))))

;end of embedding code.  The following are
;some utilities, written in Schelog

(define %member
  (lambda (x y)
    (%let (xs z zs)
      (%or
	(%= y (cons x xs))
	(%and (%= y (cons z zs))
	  (%member x zs))))))

(define %if-then-else
  (lambda (p q r)
    (%cut-delimiter
      (%or
	(%and p ! q)
	r))))

;the above could also have been written in a more
;Prolog-like fashion, viz.

'(define %member
  (%rel (x xs y ys)
    ((x (cons x xs)))
    ((x (cons y ys)) (%member x ys))))

'(define %if-then-else
  (%rel (p q r)
    ((p q r) p ! q)
    ((p q r) r)))

(define %append
  (%rel (x xs ys zs)
    (('() ys ys))
    (((cons x xs) ys (cons x zs))
      (%append xs ys zs))))

(define %repeat
  ;;failure-driven loop
  (%rel ()
    (())
    (() (%repeat))))

; deprecated names -- retained here for backward-compatibility

(define == %=)
(define %notunify %/=)

(define %eq %=:=)
(define %gt %>)
(define %ge %>=)
(define %lt %<)
(define %le %<=)
(define %ne %=/=)
(define %ident %==)
(define %notident %/==)
(define-syntax %exists (syntax-rules () ((%exists vv g) g)))

;end of file


(define %father
  (%rel ()
    (('terach 'abraham)) (('terach 'nachor)) (('terach 'haran))
    (('abraham 'isaac)) (('haran 'lot)) (('haran 'milcah))
    (('haran 'yiscah))))

;(%mother X Y) :- X is the mother of Y.

(define %mother
  (%rel () (('sarah 'isaac))))

(define %male
  (%rel ()
    (('terach)) (('abraham)) (('isaac)) (('lot)) (('haran)) (('nachor))))

(define %female
  (%rel ()
    (('sarah)) (('milcah)) (('yiscah))))

;AoP, ch. 17.  Finding all the children of a particular
;father.  (%children F CC) :- CC is the list of children
;whose father is F.  First approach: %children-1 uses an
;auxiliary predicate %children-aux, which uses an
;accumulator.

(define %children-1

  (letrec ((children-aux
	     (%rel (x a cc c)
	       ((x a cc)
                 (%father x c) (%not (%member c a)) !
                 (children-aux x (cons c a) cc))
	       ((x cc cc)))))

    (%rel (x cc)
      ((x cc) (children-aux x '() cc)))))

(define terachs-kids-test
  ;find all the children of Terach.  Returns
  ;cc = (abraham nachor haran)
  (lambda ()
    (%which (cc)
      (%children-1 'terach cc))))

(define dad-kids-test
  ;find a father and all his children.  Returns
  ;f = terach, cc = (haran nachor abraham).
  ;(%more) fails, showing flaw in %children-1.
  ;see AoP, ch. 17, p. 267
  (lambda ()
    (%which (f cc)
      (%children-1 f cc))))

(define terachs-kids-test-2
  ;find all the kids of Terach, using %set-of.
  ;returns kk = (abraham nachor haran)
  (lambda ()
    (%let (k)
      (%which (kk)
        (%set-of k (%father 'terach k) kk)))))

;This is a better definition of the %children predicate.
;Uses set predicate %bag-of

(define %children
  (%rel (x kids c)
    ((kids) (%set-of c (%father x c) kids))))

(define dad-kids-test-2
  ;find each dad-kids combo.
  ;1st soln: dad = terach, kids = (abraham nachor haran)
  ;(%more) gives additional solutions.
  (lambda ()
    (%let (x)
      (%which (dad kids)
        (%set-of x (%free-vars (dad)
                     (%father dad x))
          kids)))))

(define dad-kids-test-3
  ;looks like dad-kids-test-2, but dad is now
  ;existentially quantified.  returns a set of
  ;kids (i.e., anything with a father)
  (lambda ()
    (%let (x)
      (%which (dad kids)
        (%set-of x (%father dad x)
          kids)))))

(define dad-kids-test-4
  ;find the set of dad-kids.
  ;since dad is existentially quantified,
  ;this gives the wrong answer: it gives
  ;one set containing all the kids
  (lambda ()
    (%let (dad kids x)
      (%which (dad-kids)
	(%set-of (list dad kids)
	  (%set-of x (%father dad x) kids)
	  dad-kids)))))

(define dad-kids-test-5
  ;the correct solution.  dad is
  ;identified as a free var.
  ;returns a set of dad-kids, one for
  ;each dad
  (lambda ()
    (%let (dad kids x)
      (%which (dad-kids)
	(%set-of (list dad kids)
	  (%set-of x (%free-vars (dad)
                       (%father dad x))
            kids)
	  dad-kids)))))

(define person
  ;;a structure-builder for persons
  (lambda (name country sport)
    (list 'person name country sport)))

(define %games
  (%rel (clues queries solution the-men
	 n1 n2 n3 c1 c2 c3 s1 s2 s3)
    ((clues queries solution)
     (%= the-men
       (list (person n1 c1 s1) (person n2 c2 s2) (person n3 c3 s3)))
     (%games-clues the-men clues)
     (%games-queries the-men queries solution))))
    
(define %games-clues
  (%rel (the-men clue1-man1 clue1-man2 clue2-man1 clue2-man2 clue3-man)
    ((the-men
       (list
	 (%did-better clue1-man1 clue1-man2 the-men)
	 (%name clue1-man1 'michael)
	 (%sport clue1-man1 'basketball)
	 (%country clue1-man2 'usa)

	 (%did-better clue2-man1 clue2-man2 the-men)
	 (%name clue2-man1 'simon)
	 (%country clue2-man1 'israel)
	 (%sport clue2-man2 'tennis)

	 (%first the-men clue3-man)
	 (%sport clue3-man 'cricket))))))

(define %games-queries
  (%rel (the-men man1 man2 aussies-name dicks-sport)
    ((the-men
       (list
	 (%member man1 the-men)
	 (%country man1 'australia)
	 (%name man1 aussies-name)

	 (%member man2 the-men)
	 (%name man2 'richard)
	 (%sport man2 dicks-sport))
       (list
	 (list aussies-name 'is 'the 'australian)
	 (list 'richard 'plays dicks-sport))))))
	 
(define %did-better
  (%rel (a b c)
    ((a b (list a b c)))
    ((a c (list a b c)))
    ((b c (list a b c)))))

(define %name
  (%rel (name country sport)
    (((person name country sport) name))))

(define %country
  (%rel (name country sport)
    (((person name country sport) country))))

(define %sport
  (%rel (name country sport)
    (((person name country sport) sport))))

(define %first
  (%rel (car cdr)
    (((cons car cdr) car))))

;This is the puzzle solver described in Sterling & Shapiro, p. 214

;As S & S say, it is a "trivial" piece of code
;that successively solves each clue and query, which are expressed
;as Prolog goals and are executed with the meta-variable facility.

;The code in "real" Prolog, for comparison, is:
;
;  solve_puzzle(Clues, Queries, Solution) 
;                 :- solve(Clues), solve(Queries).
;
;  solve([Clue|Clues]) :- Clue, solve(Clues).
;  solve([]).

(define %solve-puzzle
  (%rel (clues queries solution)
    ((clues queries solution)
      (%solve clues)
      (%solve queries))))

(define %solve
  (%rel (clue clues)
    (((cons clue clues))
      clue 
      (%solve clues))
    (('()))))

;evaluate (solve-puzzle %puzzle) to get the solution to
;%puzzle.  Here %puzzle is a relation that is defined to
;hold for the three arguments clues, queries and solution=,
;iff they satisfy the constraints imposed by the puzzle.
;solve-puzzle finds an (the?) instantiation for the solution=
;variable.

(define solve-puzzle
  (lambda (%puzzle)
    (%let (clues queries)
      (%which (solution=)
	(%and
	  (%puzzle clues queries solution=)
	  (%solve-puzzle clues queries solution=))))))

(solve-puzzle %games)
