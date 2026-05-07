;Retrieved from https://github.com/ekmett/scheme-monads and flattened into one file
;There was no copyright notice in the repository
;
;; Edward Kmett (8/28/09)
;; A poor man's testing framework

(define-syntax assert
  (syntax-rules ()
    ((assert proposition) 
       (when (not proposition) 
         (begin
           (display "Assertion Failed: ")
           (display 'proposition)
           (newline))))))

(define-syntax assert-eq
  (syntax-rules ()
    ((assert-eq x y) (assert (equal? x y)))))
;; Edward Kmett
;; curried lambdas w/ under- and over- application.

;; curried lambda
(define-syntax curried
  (syntax-rules ()
    ((_ () body)
     (lambda args
         (if (null? args)
             body
             apply body args)))
    ((_ (arg) body)
      (letrec 
        ((partial-application 
          (lambda args  
            (if (null? args) 
                partial-application
                (let ((arg (car args)) 
                      (rest (cdr args)))
                  (if (null? rest)
                      body 
                      (apply body rest)))))))
        partial-application))
    ((_ (arg args ...) body)
     (letrec
       ((partial-application 
         (lambda all-args
           (if (null? all-args) 
               partial-application
               (let ((arg (car all-args))
                     (rest (cdr all-args)))
                 (let ((next (curried (args ...) body)))
                   (if (null? rest)
                       next
                       (apply next rest))))))))
       partial-application))))

;; curried defines
(define-syntax define-curried
  (syntax-rules ()
    ((define-curried (name args ...) body)
       (define name (curried (args ...) body)))
    ((define-curried (name) body)
       (define name (curried () body)))
    ((define-curried name body)
       (define name body))))
;;; Code written by Oleg Kiselyov
;; (http://pobox.com/~oleg/ftp/)
;;;
;;; Taken from leanTAP.scm
;;; http://kanren.cvs.sourceforge.net/kanren/kanren/mini/leanTAP.scm?view=log

; A simple linear pattern matcher
; It is efficient (generates code at macro-expansion time) and simple:
; it should work on any R5RS Scheme system.

; (pmatch exp <clause> ...[<else-clause>])
; <clause> ::= (<pattern> <guard> exp ...)
; <else-clause> ::= (else exp ...)
; <guard> ::= boolean exp | ()
; <pattern> :: =
;        ,var  -- matches always and binds the var
;                 pattern must be linear! No check is done
;         _    -- matches always
;        'exp  -- comparison with exp (using equal?)
;        exp   -- comparison with exp (using equal?)
;        (<pattern1> <pattern2> ...) -- matches the list of patterns
;        (<pattern1> . <pattern2>)  -- ditto
;        ()    -- matches the empty list

(define-syntax pmatch
  (syntax-rules (else guard)
    ((_ (rator rand ...) cs ...)
     (let ((v (rator rand ...)))
       (pmatch v cs ...)))
    ((_ v) (error 'pmatch "failed: ~s" v))
    ((_ v (else e0 e ...)) (begin e0 e ...))
    ((_ v (pat (guard g ...) e0 e ...) cs ...)
     (let ((fk (lambda () (pmatch v cs ...))))
       (ppat v pat (if (and g ...) (begin e0 e ...) (fk)) (fk))))
    ((_ v (pat e0 e ...) cs ...)
     (let ((fk (lambda () (pmatch v cs ...))))
       (ppat v pat (begin e0 e ...) (fk))))))

(define-syntax ppat
  (syntax-rules (quote unquote)
    ((_ v _ kt kf) kt)
    ((_ v () kt kf) (if (null? v) kt kf))
    ((_ v (quote lit) kt kf) (if (equal? v (quote lit)) kt kf))
    ((_ v (unquote var) kt kf) (let ((var v)) kt))
    ((_ v (x . y) kt kf)
     (if (pair? v)
       (let ((vx (car v)) (vy (cdr v)))
	 (ppat vx x (ppat vy y kt kf) kf))
       kf))
    ((_ v lit kt kf) (if (equal? v (quote lit)) kt kf))))
;; Edward Kmett (8/28/09)

;; Basic definitions for:
;; functor
;;  pointed
;;   applicative
;;    alternative
;;    monad
;;     monad-plus
;;  copointed
;;   comonad

;; Uses positional dictionaries, placing misc methods stuff in an alist.
;; Nothing outside of this module concerns itself with how we handle dispatch.

                         
;; I combinator
(define-curried (id x) x)

;; function composition
(define-curried (compose f g x) (f (g x)))

;; a valid functor map operation for any monad
(define-curried (make-monad-fmap unit star f) 
  (star (compose unit f)))

;; a valid functor map operation for any applicative
(define-curried (make-applicative-fmap unit ap f)
  (ap (unit f)))

;; a valid functor map operation for any comonad
(define-curried (make-comonad-fmap tinu rats f) 
  (rats (compose f tinu)))

;; these can obviously be simplified and coalesced into a coherent whole
(define-curried (functor fmap) 
  (list '() fmap))

(define-curried (pointed fmap unit)
  (list '() fmap (list unit)))

(define-curried (applicative unit ap)
  (list '() (make-applicative-fmap unit ap) (list unit ap)))

(define-curried (functor-zero fmap zero)
  (list '() fmap '() (list zero)))

(define-curried (functor-plus fmap zero plus)
  (list '() fmap '() (list zero plus)))

(define-curried (alternative unit ap zero plus)
  (list '() (make-applicative-fmap unit ap) (list unit ap) (list zero plus)))
  
(define-curried (monad unit star)
  (let ((fmap (make-monad-fmap unit star)))
    (list '() fmap (list unit (make-monad-ap fmap star) star))))

;; monad-plus f = (
;;    alist,                                  -- attributes 
;;    (forall a b. (a -> b) * f a -> f b),    -- fmap
;;                                            -- multiplication
;;    ((forall a. a -> f a),                    -- unit
;;     (forall a b. f (a -> b) -> f a -> f b),  -- ap
;;     (forall a b. (a -> f b) * f a -> f b)),  -- star
;;                                            -- addition
;;    ((forall a. f a),                         -- zero
;;     (forall a. f a -> f a -> f a)))          -- plus

(define-curried (monad-plus unit star zero plus)
  (let ((fmap (make-monad-fmap unit star)))
    (list '() fmap (list unit (make-monad-ap fmap star) star) (list zero plus))))
       
;; the categorical dual of a monad
;; comonad f = (
;;    alist,                                 -- attributes 
;;    (forall a b. (a -> b) * f a -> f b),   -- fmap
;;                                           -- multiplication
;;    ((forall a. f a -> a),                   -- tinu
;;     (forall a b. (f a -> b) * f a -> f b))) -- rats
 
(define-curried (copointed fmap tinu)
  (list '() fmap (list tinu)))

(define-curried (comonad tinu rats)
  (list '() (make-comonad-fmap tinu rats) (list tinu rats)))

;; fmap :: functor f ~> (a -> b) ~> f a -> f b
(define-curried (fmap functor f x) 
  ((cadr functor) f x))

;; unit :: monad m ~> a -> m a
(define-curried (unit monad x) 
  ((car (caddr monad)) x))

;; ap :: monad m ~> m (a -> b) ~> m a -> m b
;; ap = lift-m2 id
(define-curried (ap monad mf mx) 
  ((cadr (caddr monad)) f m))

  ;; star :: monad m ~> (a -> m b) ~> m a -> m b
(define-curried (star monad f m) 
  ((caddr (caddr monad)) f m))

;; zero :: monad-plus m -> m a
(define-curried (zero monad) (car (cadddr monad)))

;; plus :: monad-plus m ~> m a ~> m a -> m a
(define-curried (plus monad m n) ((cadr (cadddr monad)) m n))

;; tinu :: comonad w ~> w a -> a
(define-curried (tinu comonad w) ((car (caddr comonad)) w))

;; rats :: comonad w ~> (w a -> b) ~> w a -> w b
(define-curried (rats comonad f w) ((cadr (caddr comonad)) f w))

;; with-attribute : (slot . value) ~> functor f -> { functor f | f[slot] = value }
(define-curried (with-attribute attrval functor)
  (cons (cons attrval (car functor)) (cdr functor)))

;; with-fmap : { xs : forall a b. (a -> b) * f a -> f b) } ~> { G : functor f } -> { F : functor f | fmap F == xs, p F == p G, otherwise} 
(define-curried (with-fmap fmap functor)
  (cons (car functor) (cons fmap (cddr functor))))

;; attribute : slot ~> functor f -> f[slot]
(define-curried (attribute attr f)
  (cdr (assv attr (car f))))

;; monad-state
(define-curried (get monad) 
  (attribute 'get monad))

(define-curried (put monad state) 
  (attribute 'put monad state))

;; monad-writer
(define-curried (tell monad log) 
  (attribute 'tell monad log))

;; monad-reader
(define-curried (ask monad) 
  (attribute 'ask monad))

;; monad-transformer
(define-curried (lift monad mx) 
  (attribute 'lift monad mx))

;; join :: monad m ~> m (m a) -> m a
(define-curried (join monad) 
  (star monad id))

;; duplicate :: comonad w ~> w a -> w (w a)
(define-curried (duplicate comonad)
  (rats comonad id))

(define-curried (make-monad-ap fmap star mf mx)
  (star (lambda (f) (fmap f mx)) mf))
  
;; lift-a2 :: applicative f ~> (a -> b -> c) ~> f a ~> f b -> m c
;; lift a binary calculation into a monad
(define-curried (lift-a2 a f mx my)
  (ap a (fmap a f mx) my))

;; Given: monad m, k = (kleisli-compose m), u = (unit monad)
;; (k f u) = f
;; (k u f) = f
;; (k (k a b) c) = k (a (k b c)
(define-curried (kleisli-compose monad f g)
  (compose (star monad f) g))

;; Given: comonad w, k = (cokleisli-compose w), u = (tinu comonad)
;; (k f u) = f
;; (k u f) = f
;; (k (k a b) c) = k (a (k b c)
(define-curried (cokleisli-compose comonad f g)
  (compose f (rats comonad g)))

;; idiom brackets
(define-syntax idiom
  (syntax-rules ()
    ((idiom a f) (unit a f))
    ((idiom a f x) (fmap a f x))
    ((idiom a f x y ...) (fold-left (ap a) (fmap a f x) y ...))))
  
;; monadic do sugar
(define-syntax do*
  (syntax-rules ()
    ((do* m comp-body) comp-body)
    ((do* m ((x0 comp0)) comp-body) (star m (lambda (x0) comp-body) comp0))
    ((do* m ((x0 comp0) (x comp) ...) comp-body)
     (star m (lambda (x0) (do* m ((x comp) ...) comp-body)) comp0))))

;; comonadic 'codo' sugar
;; NB: since tinu and rats occupy the same positional slots as unit and star, this could be elided.
(define-syntax od*
  (syntax-rules ()
    ((od* m comp-body) comp-body)
    ((od* m ((x0 comp0)) comp-body) (rats m (lambda (x0) comp-body) comp0))
    ((od* m ((x0 comp0) (x comp) ...) comp-body)
     (rats m (lambda (x0) (od* m ((x comp) ...) comp-body)) comp0))))

(define-curried (gets monad f)
  (fmap monad f (get monad)))

(define-curried (asks monad f)
  (fmap monad f (ask monad)))

(define-curried (modify monad f)
  (star monad (lambda (x) (put monad (f x))) (get monad)))
;; A Church-encoded maybe monad
;; Edward Kmett (8/28/09)


;; type church-maybe a = forall b. b * (a -> b) -> b

;; church-maybe-unit : a -> church-maybe a
(define-curried (church-maybe-unit x _ f) 
  (f x))

;; church-maybe-star : (a -> church-maybe b) -> church-maybe a -> church-maybe b
(define-curried (church-maybe-star k m z f)
  ((m z k) z f))

;; church-maybe-zero : church-maybe a
(define-curried (church-maybe-zero z _) 
  z)

;; church-maybe-plus : church-maybe a -> church-maybe a -> church-maybe a
(define-curried (church-maybe-plus m n z f)
  (m (n z f) f))

;; church-maybe : monad church-maybe
(define church-maybe 
  (monad-plus church-maybe-unit church-maybe-star church-maybe-zero church-maybe-plus))

;; run-church-maybe : b -> (a -> b) -> church-maybe a -> b
(define-curried (run-church-maybe z f m)
  (m z f))

;; The Identity Monad
;; Edward Kmett (8/28/09)


(define id-monad (monad id id))
(define id-comonad (comonad id id))
;; The List Monad
;; Edward Kmett (8/28/09)


;; append-map :: (a -> [b]) -> [a] -> [b]
(define-curried (append-map f xs)
  (apply append (map f xs)))

;; list-monad : monad-plus []
(define list-monad 
  (monad-plus list append-map '() append))

(assert-eq 
 '(2 4 4 5) 
 (do* list-monad ((x '(1 2))) 
      (list (* 2 x) (+ 3 x))))
;; Tagged Maybe Monad
;; Edward Kmett (8/28/09)


;; type maybe a = ('just . a) | 'nothing

;; just : a -> maybe a
(define-curried (just x) (cons 'just x))

;; nothing : maybe a
(define nothing 'nothing)

;; maybe-star : (a -> maybe b) -> maybe a -> maybe b
(define-curried (maybe-star f m)
  (if (eqv? 'nothing m) nothing (f (cdr x))))

;; maybe-plus : maybe a -> maybe a -> maybe a
(define-curried (maybe-plus m n)
  (if (eqv? m 'nothing) n m))

;; maybe : monad-plus maybe
(define maybe
  (monad-plus just maybe-star nothing maybe-plus))
;; The Product Comonad
;; Edward Kmett (8/28/09)


(define product-comonad
  (comonad 
    ;; tinu
    cdr 
    ;; rats
    (lambda (f p)
      (cons (car p) (f p)))))
  
(assert-eq 
    (cons 6 90)
    (rats product-comonad (lambda (p) (* (car p) (tinu product-comonad p))) (cons 6 15)))
;; The Reader Monad
;; Edward Kmett (8/28/09)


;; type reader e a = e -> a

;; const :: a -> e -> a 
;; K combinator
(define-curried (const x _) x)
  
;; reader-star :: (a -> reader e b) -> reader e a -> reader e b
;; reader-star :: (a -> e -> b) -> (e -> a) -> e -> b

;; note the relation of reader-star to the S combinator:
;; first argument flipped
;; S :: (e -> a -> b) -> (e -> a) -> e -> b
;; (define-curried (S x y z) (x z (y z)))

(define-curried (reader-star f r e)
  ((f (r e)) e))
  
;; reader :: monad (reader e)
(define reader
  (with-attribute (cons 'ask id) 
     (monad const reader-star)))

(assert-eq 3
    ((do* reader ((x (unit reader 1)) (y (ask reader))) (const (+ x y))) 2))
;; Edward Kmett (8/29/08)
;; The state monad


;; type state s a = s -> (a . s)

;; state-unit : a -> state s a
(define-curried (state-unit a s) (cons a s))

;; state-star : (a -> state s b) ~> state s a -> state s b
;; state-star : (a -> s -> (b . s)) -> (s -> (a . s)) -> s -> (b . s)
(define-curried (state-star f ma s)
  (let ((t (ma s)))
    ((f (car t)) (cdr t))))

;; state-get : state s s
(define-curried (state-get s) (cons s s))

;; state-put : s -> state s s 
(define-curried (state-put a _) (cons a a))

(define state-monad
  (with-attribute (cons 'get state-get)
    (with-attribute (cons 'put state-put)
      (monad state-unit state-star))))
;; The Trivial Monad
;; Edward Kmett (8/28/09)


(define nil '())

;; does nothing
(define trivial-monad
  (monad-plus 
     (lambda (x) nil)
     (lambda (k m) nil)
     nil
     (lambda (m n) nil)))
;; The Writer Monad
;; Edward Kmett (8/28/09)


;; make a writer monad given a monoid specified by its unit
;; and associative binary operation. The binary operation should
;; be able to take both arguments in one application. So should
;; be defined either using the curried macro or as taking two 
;; arguments
(define-curried (make-writer e op)
  (with-attribute (cons 'tell (lambda (x) (cons x '())))
    (monad
          ;; unit
          (lambda (x) (cons e x))
          ;; star
          (lambda (f m) 
              (let ((r (f (cdr m))))
                (cons (op (car m) (car r)) (cdr r)))))))

(assert-eq '(5)
   (let ((w (make-writer 0 (lambda (x y) (+ x y)))))
       (do* w ((x (unit w 1)) (y (tell w x))) (tell w 4))))


;; the cofree comonad has the form (a . f (a . f (a . f (....))))
;; the prod-type ideal comonad is categorically dual to the free monad.

;; the cofree comonad of a functor
(define-curried (make-cofree-comonad functor)
  (let ((map (fmap functor)))
    (comonad
      ;; tinu
      car
      ;; rats 
      (curried (f) ;; the use of curried propagates second argument to lambda (w) below.
        (letrec ((alpha (lambda (w)
                          (cons (f w) (map alpha (cdr w))))))
          alpha)))))

;; when the functor f has a natural notion of zero and plus, we can build a monad out of it as well!

;; The prod-type monad given rise to by a functor w/ a monoidal structure (functor-plus)
(define-curried (make-cofree-monad fp)
  (let ((base-map (fmap fp)) (base-zero (zero fp)) (base-plus (plus fp)))
    (monad
      ;; unit 
      (lambda (x) (cons x base-zero))
      ;; star
      (curried (f) ;; use of curried propagates second argument to lambda (m) below.
        (letrec
          ((alpha (lambda (m)
                    (let ((r (f (car m))))
                         (cons (car r) (base-plus (base-map alpha (cdr m)) (cdr r))))))) 
          alpha)))))
     
(assert-eq
   '(1 (2 (3) (4)) (3 (4) (5)) (2) (3))
   (let ((cofree-list (make-cofree-monad list-monad)))
     (let ((act ((star cofree-list (lambda (x) (cons x (list (unit cofree-list (+ x 1)) (unit cofree-list (+ x 2)))))))))
       (act (act (unit cofree-list 1))))))

;; yoneda-fmap : (a -> c) -> ((a -> b) -> f b) -> (c -> b) -> f b
(define-curried (yoneda-fmap f m k)
  (m (compose k f)))

;; yoneda f a = (forall b. (a -> b) -> f b)
;; 'yoneda f' is a functor regardless of the definition of f!
(define yoneda-functor (functor yoneda-fmap))

;; construct the unit of a yoneda monad of a given monad
(define-curried (make-yoneda-unit base-monad f)
  (unit base-monad (f a)))

;; construct the star of a yoneda monad for a given monad
;; make-yoneda-star : monad f ~> (a -> yoneda f b) ~> yoneda f a -> yoneda f b
;; make-yoneda-star : monad f ~> (a -> forall b. (b -> c) -> f c) ~> (forall d. (a -> d) -> f d) ~> forall e. (a -> e) -> f e
(define-curried (make-yoneda-star base-monad k m f)
  (star base-monad (lambda (a) ((k a) f)) (m id)))

;; lower-yoneda : yoneda f a -> f a
;; lower-yoneda : (forall b. (a -> b) -> f b) -> f a
(define-curried (yoneda-lower f)
  (f id))

;; make-yoneda-ap : applicative f => yoneda f (a -> b) -> yoneda f a -> yoneda f b
;; make-yoneda-ap : (forall c. ((a -> b) -> c) -> f c) -> 
;;                  (forall d. (a -> d) -> f d) ->
;;                  (forall e. (a -> e) -> f e)
(define-curried (make-yoneda-ap a mg mx f)
  (ap a (mg (compose f)) (mx id)))

;; to-yoneda : functor f => f a -> yoneda f a
(define-curried (make-yoneda-lift base-functor fa ab)
  (fmap base-functor ab fa))

(define-curried (make-yoneda-zero base-monad _)
  (zero base-monad))

(define-curried (make-yoneda-plus base-monad m n f)
  (fmap base-monad f (plus base-monad (m id) (n id))))
      
;; 'yoneda f' is a monad if f is a monad.
;; TODO: lift the underlying attributes
;; TODO: make the resulting dictionary only have entries the source dictionary has
(define-curried (make-yoneda m)
  (list 
    (list 
      ;; TODO lift the other operations of the base monad
      (cons 'lift (make-yoneda-lift m))) 
    yoneda-fmap
    (list
      (make-yoneda-unit m)
      (make-yoneda-ap m)
      (make-yoneda-star m))
    (list
      (make-yoneda-zero m)
      (make-yoneda-plus m))))

(assert-eq 
  '(2 4 4 5) 
  (let ((yoneda (make-yoneda list-monad)))
    (yoneda-lower 
      (do* yoneda 
           ((x (lift yoneda '(1 2))))
           (lift yoneda (list (* 2 x) (+ 3 x))))))) 

;; Bring into scope all of the monads
;; TODO: examples
;; TODO: monad transformers
;; TODO: comonad transformers

;; monads
;; (load "cont.scm")
;; (load "free.scm")
;; (load "random.scm")
;; codensity-state

;; comonads
;; (load "context.scm")
;; (load "exp.scm")


;; both
;; (load "coyoneda.scm")
;; (load "density.scm")
;; (load "codensity.scm")
