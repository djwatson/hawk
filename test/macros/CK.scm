; Composable syntax-rules macros via the CK abstract machine
;
; We demonstrate (mutually-) recursive, higher-order applicative
; macros with clausal definitions, defined in the style that looks very 
; much like that of ML or (strict) Haskell.
; We write composable, call-by-value--like macros without
; resorting to the continuation-passing-style and thus requiring no 
; macro-level lambda. The syntax remains direct-style, with 
; nested applications.

; This project was the answer to the question posed by Dan Friedman
; on Mar 20, 2009:
;    Write the macro 'permute' that takes any number of arguments and returns
;    the list of their permutations
;
;      (permute a b c) ==> ((a b c) (b a c) (b c a) (a c b) (c a b) (c b a))
;    The order of the entries in the list is immaterial. One should write
;    permute without resorting to CPS.
;
; Our answer is the transliteration of the standard Haskell code
; implementing the straightforward algorithm for all permutations:
;   perm :: [a] -> [[a]]
;   perm [] = [[]]
;   perm (h:t) = concatMap (ins h) (perm t)
;   ins :: a -> [a] -> [[a]]
;   ins x [] = [[x]]
;   ins x (h:t) = (x:h:t) : map (h:) (ins x t)
; We shall see that our code looks pretty much like the above,
; but with more parentheses.


; Our macros should are written in a specific, CK style.
; Here is the first example.
; The macro may have an arbitrary number of arguments; the following c-cons
; macro has two arguments. In addition, every CK macro must take
; an argument, typically called 's', which it should not touch;
; This 's' argument is always the first argument.
; A CK macro should pass the received 's' argument to the ck macro below.
; All arguments except the 's' argument have the form 
;   (quote <exp>)
; meaning that they are _values_ of the CK machine.
; A CK macro always ends in a call to the macro ck passing
; it the s argument followed by the produced value or by an expression
; that will produce the resulting value.
; The macro c-cons produces a value, which is therefore quoted:
(define-syntax c-cons
  (syntax-rules (quote)
    ((c-cons s 'h 't) (ck s '(h . t)))))

; We define a macro c-append, using the just defined c-cons.
; We demonstrate recursion, clausal definition, and 
; functional composition, or nested application.
; The first clause yields a value, which is quoted.
; The second clause yields an expression that will produce the value.
; The expression is not quoted. Again, a CK-style macro must always
; expand into the call to the 'ck' macro.
(define-syntax c-append
  (syntax-rules (quote)
    ((c-append s '() 'l2)       (ck s 'l2))   ; return a value
    ((c-append s '(h . t) 'l2)  (ck s (c-cons 'h (c-append 't 'l2))))
))

; The code does look like Haskell code
; append [] l2    = l2
; append (h:t) l2 = h : (append t l2)


; The CK machine
; The machine does focusing and refocusing, relying on
; user-defined CK-style macros for (primitive) reductions.
;
; A stack frame (op va ... [] ea ...) is represented in the code as
;    ((op va ...) ea ...)
; where op is the name of a CK-style macro that does the reduction.
; zero or more va must all be values
; zero or more ea are arbitrary expressions (could be applications or values)

(define-syntax ck
  (syntax-rules (quote)
    ((ck () 'v) v)			; yield the value on empty stack

    ((ck (((op ...) ea ...) . s) 'v)	; re-focus on the other argument, ea
      (ck s "arg" (op ... 'v) ea ...))

    ((ck s "arg" (op va ...))		; all arguments are evaluated,
      (op s va ...))			; do the redex

    ((ck s "arg" (op ...) 'v ea1 ...)	; optimization when the first ea
      (ck s "arg" (op ... 'v) ea1 ...)) ; was already a value

    ((ck s "arg" (op ...) ea ea1 ...)	; focus on ea, to evaluate it
      (ck (((op ...) ea1 ...) . s) ea))

    ((ck s (op ea ...))			; Focus: handling an application;
      (ck s "arg" (op) ea ...))		; check if args are values
))


; We get the ball rolling by invoking
;  (ck () exp)
; to expand the CK-expression given the empty initial stack.
;
; If we evaluate the following
; (ck () (c-append '(1 2 3) '(4 5)))
; the macro-expansion hopefully produces (1 2 3 4 5)
; Then the evaluator will try to evaluate the result of the macro-expansion,
; reporting the error since 1 is not a procedure.
; If we want to see the result of only the macro-expansion, without
; any further evaluation, we should quote it

(define-syntax c-quote
  (syntax-rules (quote)
    ((c-quote s 'x) (ck s ''x))))


(ck () (c-quote (c-append '(1 2 3) '(4 5))))
; ==> (1 2 3 4 5)

; A higher-order macro: map
(define-syntax c-map
  (syntax-rules (quote)
    ((c-map s 'f '())      (ck s '()))
    ((c-map s '(f ...) '(h . t)) 
      (ck s (c-cons (f ... 'h) (c-map '(f ...) 't))))
))

(ck () (c-quote (c-map '(c-cons '10) '((1) (2) (3) (4)))))
; ==> ((10 1) (10 2) (10 3) (10 4))

(define-syntax c-concatMap
  (syntax-rules (quote)
    ((c-concatMap s 'f '())      (ck s '()))
    ((c-concatMap s '(f ...) '(h . t)) 
      (ck s (c-append (f ... 'h) (c-concatMap '(f ...) 't))))
))

(ck () (c-quote (c-concatMap '(c-cons '10) '((1) (2) (3) (4)))))
; ==> (10 1 10 2 10 3 10 4)


; We now solve Dan Friedman's problem, by transliterating the Haskell
; code for all permutations.

(define-syntax c-perm
  (syntax-rules (quote)
    ((c-perm s '()) (ck s '(())))
    ((c-perm s '(h . t)) (ck s (c-concatMap '(c-ins 'h) (c-perm 't))))))

(define-syntax c-ins
  (syntax-rules (quote)
    ((c-ins s 'x '()) (ck s '((x))))
    ((c-ins s 'x '(h . t)) 
      (ck s (c-cons '(x h . t) (c-map '(c-cons 'h) (c-ins 'x 't)))))))

; The following macro is a syntactic sugar to invoke c-perm
(define-syntax perm
  (syntax-rules ()
    ((perm . args) (ck () (c-quote (c-perm 'args))))))


; Tests

(perm)
; (())

(perm 1)
; ((1))

(perm 1 2)
; ((1 2) (2 1))

(perm 1 2 3)
; ((1 2 3) (2 1 3) (2 3 1) (1 3 2) (3 1 2) (3 2 1))

(perm 1 2 3 4)
;; ((1 2 3 4)
;;  (2 1 3 4)
;;  (2 3 1 4)
;;  (2 3 4 1)
;;  (1 3 2 4)
;;  (3 1 2 4)
;;  (3 2 1 4)
;;  (3 2 4 1)
;;  (1 3 4 2)
;;  (3 1 4 2)
;;  (3 4 1 2)
;;  (3 4 2 1)
;;  (1 2 4 3)
;;  (2 1 4 3)
;;  (2 4 1 3)
;;  (2 4 3 1)
;;  (1 4 2 3)
;;  (4 1 2 3)
;;  (4 2 1 3)
;;  (4 2 3 1)
;;  (1 4 3 2)
;;  (4 1 3 2)
;;  (4 3 1 2)
;;  (4 3 2 1))


; ------------------------------------------------------------------------
; No Computer Science paper is complete without a factorial
; The following computes the factorial of naturals encoded in unary:
; for example, (u u u u u) encodes the number 5.
; Compare the direct-style macro below with the CPS macro,
; Macros-talk.pdf, slide 17.

; adding unary numerals is appending the corresponding lists
(define-syntax c-add
  (syntax-rules ()
    ((c-add . args) (c-append . args))))

(define-syntax c-mul
  (syntax-rules (quote u)
    ((c-mul s '() 'y)  (ck s '()))	; 0 * y = 0
    ((c-mul s '(u) 'y) (ck s 'y))       ; 1 * y = y
    ((c-mul s '(u . x) 'y)		; (1+x) * y = y + x*y
      (ck s (c-add 'y (c-mul 'x 'y))))))


(ck () (c-quote (c-mul '(u u) '(u u u))))
; ==> (u u u u u u)

(define-syntax c-fact
  (syntax-rules (quote u)
    ((c-fact s '())  (ck s '(u)))
    ((c-fact s '(u)) (ck s '(u)))
    ((c-fact s '(u . n)) (ck s (c-mul '(u . n) (c-fact 'n))))))

(ck () (c-quote (c-fact '(u u u u))))
; ==> (u u u u u u u u u u u u u u u u u u u u u u u u)


; ------------------------------------------------------------------------
; Systematic development of a complex DSL macro delete-assoc
; (a part of the SSAX:make-parser)
;
; (delete-assoc ALIST KEY) deletes an association with the name KEY from
; ALIST, a list of (name . value) pairs. The macro returns the list of 
; the remaining associations. KEY not found => error
;
; Compare the direct-style macro below with the huge CPS-style macro
; on p20 of Macros-talk.pdf

; A symbol-eq? predicate at the macro-expand time
;	symbol-eq? S1 S2 KT KF
; (where S1 must be a symbol)
; expands into KT if S1 and S2 are the same symbol (identifier);
; Otherwise, it expands into KF

(define-syntax symbol-eq?
  (syntax-rules ()
    ((symbol-eq? s1 s2 kt kf)
      (let-syntax
	((test
	   (syntax-rules (s1)
	     ((test s1 _kt _kf) _kt)
	     ((test otherwise _kt _kf) _kf))))
	(test s2 kt kf)))))

(define-syntax c-delete-assoc
  (syntax-rules (quote)
    ((c-delete-assoc s '((h . e) . t) 'key)
      (symbol-eq? key h
	(ck s 't)
	(ck s (c-cons '(h . e) (c-delete-assoc 't 'key)))))))


; convenience macro
(define-syntax delete-assoc
  (syntax-rules ()
    ((delete-assoc lst key) (ck () (c-quote (c-delete-assoc 'lst 'key))))))

(delete-assoc
  ((NEW-LEVEL-SEED . nls-proc)
   (FINISH-ELEMENT . fe-proc)
   (UNDECL-ROOT . ur-proc))
  FINISH-ELEMENT)
; ==> ((NEW-LEVEL-SEED . nls-proc)
;      (UNDECL-ROOT . ur-proc))


