(import (only (scheme base)
              or
              and
              define
              unless
              cond
              include
              let
              let*
              if
              begin
              quote
              do
              when
              else
              =>
              set!
              lambda
              define-syntax
              syntax-rules
              case
              ...
              define-record-type)
        ;; TODO
        (scheme complex)
        (scheme case-lambda)
        (prefix (hawk sys) sys:))

(define (truncate x) (sys:TRUNCATE x))
(define (inexact x) (sys:INEXACT x))
(define (exact x) (sys:EXACT x))
(define (char->integer x) (sys:CHAR_INTEGER x))
(define (integer->char x) (sys:INTEGER_CHAR x))

(define (floor x)
  (cond
    ((flonum? x) (sys:FOREIGN_CALL '(double "floor" (double)) x))
    ;((ratnum? x) (floor-quotient (numerator x) (denominator x)))
    (else x)))
(define (exp num) (sys:FOREIGN_CALL '(double "exp" (double)) (inexact num)))

(define (reducer f init args)
  (let loop ((init init) (args args))
    (if (pair? args) (loop (f init (car args)) (cdr args)) init)))

(define (quotient a b) (sys:QUOTIENT a b))
(define (modulo x y)
  (let ((z (remainder x y)))
    (if (negative? y) (if (positive? z) (+ z y) z) (if (negative? z) (+ z y) z))))
(define (remainder a b) (sys:MOD a b))
(define +
  (case-lambda
    (() 0)
    ((a) a)
    ((a b) (sys:ADD a b))
    ((a b c) (sys:ADD (sys:ADD a b) c))
    (rest (reducer (lambda (a b) (sys:ADD a b)) 0 rest))))

(define -
  (case-lambda
    ((a) (sys:MUL -1 a))
    ((a b) (sys:SUB a b))
    ((a . rest) (reducer (lambda (a b) (sys:SUB a b)) a rest))))

(define *
  (case-lambda
    (() 1)
    ((a) a)
    ((a b) (sys:MUL a b))
    ((a b c) (* (* a b) c))
    (rest (reducer (lambda (a b) (sys:MUL a b)) 1 rest))))

(define / (case-lambda ((a) (sys:DIV 1.0 a)) ((a b) (sys:DIV a b))))

(define (comparer f args)
  (let loop ((args args))
    (if (and (pair? args) (pair? (cdr args)))
        (if (f (car args) (cadr args)) (loop (cdr args)) #f)
        #t)))

(define <
  (case-lambda
    ((a b) (sys:LT a b))
    (rest (comparer (lambda (a b) (sys:LT a b)) rest))))
(define >
  (case-lambda
    ((a b) (sys:GT a b))
    (rest (comparer (lambda (a b) (sys:GT a b)) rest))))
(define <=
  (case-lambda
    ((a b) (sys:LTE a b))
    (rest (comparer (lambda (a b) (sys:LTE a b)) rest))))
(define >=
  (case-lambda
    ((a b) (sys:GTE a b))
    (rest (comparer (lambda (a b) (sys:GTE a b)) rest))))
(define =
  (case-lambda
    ((a b) (sys:EQV a b))
    (rest (comparer (lambda (a b) (sys:EQV a b)) rest))))

(define (eq? a b) (sys:EQ a b))

(define (list? x)
  (let loop ((fast x) (slow x))
    (or (null? fast)
       (and (pair? fast)
            (let ((fast (cdr fast)))
              (or (null? fast)
                 (and (pair? fast)
                      (let ((fast (cdr fast)) (slow (cdr slow)))
                        (and (not (eq? fast slow)) (loop fast slow))))))))))

(define for-each
  (case-lambda
    ((proc lst)
      ;(unless (list? lst) (error "circular for-each"))
      (let loop ((proc proc) (lst lst))
        (unless (null? lst) (proc (car lst)) (loop proc (cdr lst)))))
    ((proc lst1 lst2)
      ;(unless (or (list? lst1) (list? lst2)) (error "circular for-each"))
      (let loop ((proc proc) (lst1 lst1) (lst2 lst2))
        (if (and (not (null? lst1)) (not (null? lst2)))
            (begin (proc (car lst1) (car lst2)) (loop proc (cdr lst1) (cdr lst2))))))
    ((proc . lsts)
      ;(unless (any list? lsts) (error "circular for-each"))
      (error "ABORT apply unimplemend")
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

(define (eqv? a b) (or (eq? a b) (and (flonum? a) (flonum? b) (= a b))))
(define (equal? a b)
  (sys:FOREIGN_CALL '(gc_obj "SCM_EQUAL" (gc_obj gc_obj)) a b))

(define (string-ref str idx) (sys:LOAD_CHAR str idx))
(define (string-set! str idx c) (sys:STORE_CHAR str c idx))
(define make-string
  (case-lambda
    ((len) (make-string len #f))
    ((len c)
      (let* ((size (+ len 17))
             (alloc_size (let loop ((n 8)) (if (>= n size) n (loop (+ n 8)))))
             (str (sys:ALLOC alloc_size 9)))
        (sys:STORE str len 0)
        (string-set! str len #\null)
        (when c (do ((i 0 (+ i 1))) ((= i len)) (string-set! str i c)))
        str))))

(define (cons a b)
  (let ((cell (sys:ALLOC 24 3))) (sys:STORE cell a 0) (sys:STORE cell b 1) cell))
(define (cons* first . rest)
  (let recur ((x first) (rest rest))
    (if (pair? rest) (cons x (recur (car rest) (cdr rest))) x)))
(define (not a) (if a #f #t))
(define (null? a) (sys:GUARD a 20))
(define (pair? a) (sys:GUARD a 3))
(define (boolean? a) (sys:GUARD a 4))
(define (char? a) (sys:GUARD a 12))
(define (fixnum? a) (sys:GUARD a 0))
(define (flonum? a) (sys:GUARD a 2))
(define (bignum? a) (sys:GUARD a 57))
(define (number? x)
  (or (fixnum? x)
     (flonum? x)
     (bignum? x) ;(ratnum? x) (compnum? x)
  ))
(define complex? number?)
(define real? number?)
(define rational? number?)
(define integer? fixnum?)
(define (exact? x) (or (fixnum? x) (bignum? x)))
(define inexact? flonum?)
(define exact-integer? fixnum?)
(define (bytevector=? a b) #f)
(define (procedure? a) (sys:GUARD a 5))
(define (string? a) (sys:GUARD a 9))
(define (bytevector? a) (sys:GUARD a 57))
(define (symbol? a) (sys:GUARD a 6))
(define (symbol->string sym) (sys:LOAD sym 0))
(define (vector? a) (sys:GUARD a 7))
(define (zero? z) (= z 0))
(define (negative? a) (< a 0))
(define (positive? a) (> a 0))
(define (abs p) (if (negative? p) (- p) p))
(define (list-tail lst k)
  (let loop ((lst lst) (k k)) (if (> k 0) (loop (cdr lst) (- k 1)) lst)))
(define (list . x) x)
(define (set-car! a b) (sys:STORE a b 0))
(define (set-cdr! a b) (sys:STORE a b 1))
(define (string-length a) (sys:LOAD a 0))
(define (car a) (unless (pair? a) (error "CAR: bad load:" a)) (sys:LOAD a 0))
(define (cdr a) (unless (pair? a) (error "CDR: bad load:" a)) (sys:LOAD a 1))
(define (cadr a) (car (cdr a)))
(define (cdar a) (cdr (car a)))
(define (caar a) (car (car a)))
(define (cddr a) (cdr (cdr a)))

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
        (if (null? lst) '() (cons (f (car lst)) (loop f (cdr lst))))))
    ((f lst1 lst2)
      (let loop ((f f) (lst1 lst1) (lst2 lst2))
        (if (or (null? lst2) (null? lst1))
            '()
            (cons (f (car lst1) (car lst2)) (loop f (cdr lst1) (cdr lst2))))))
    (lst
      (let loop ((lsts (cons (cadr lst) (cddr lst))))
        (let ((hds
                 (let loop2 ((lsts lsts))
                   (if (null? lsts)
                       '()
                       (let ((x (car lsts)))
                         (and (not (null? x))
                              (let ((r (loop2 (cdr lsts)))) (and r (cons (car x) r)))))))))
          (if hds
              (cons (apply (car lst) hds)
                    (loop (let loop3 ((lsts lsts))
                            (if (null? lsts) '() (cons (cdr (car lsts)) (loop3 (cdr lsts)))))))
              '()))))))
(define (append2 a b) (if (null? a) b (cons (car a) (append2 (cdr a) b))))

(define append
  (case-lambda
    ((a b) (append2 a b))
    ((a b c) (append a (append b c)))
    ((a b c d) (append a (append b (append c d))))
    (lsts
      (if (null? lsts)
          '()
          (let loop ((lsts lsts))
            (if (null? (cdr lsts))
                (car lsts)
                (let copy ((node (car lsts)))
                  (if (pair? node) (cons (car node) (copy (cdr node))) (loop (cdr lsts))))))))))
(define (reverse lst)
  (let loop ((lst lst) (res '()))
    (if (pair? lst) (loop (cdr lst) (cons (car lst) res)) res)))
(define (list-ref lst n)
  (let loop ((lst lst) (n n)) (if (zero? n) (car lst) (loop (cdr lst) (- n 1)))))
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
(define (vector-map fun vec)
  (let ((res (make-vector (vector-length vec))))
    (do ((i 0 (+ i 1)))
         ((= i (vector-length res)) res)
         (vector-set! res i (fun (vector-ref vec i))))))
;; SIN
(define two-pi 6.28319)
(define pi (/ two-pi 2.0))
(define neg-pi (sys:MUL -1.0 pi))
(define half-pi (/ pi 2.0))
(define neg-half-pi (sys:MUL -1.0 half-pi))

(define (sin-poly x)
  ;; 9th-order odd polynomial around 0:
  ;; x - x^3/6 + x^5/120 - x^7/5040 + x^9/362880
  (let* ((x2 (sys:MUL x x))
         (x3 (sys:MUL x2 x))
         (x5 (sys:MUL x3 x2))
         (x7 (sys:MUL x5 x2))
         (x9 (sys:MUL x7 x2)))
    (+ x
       (+ (sys:MUL -0.166667 x3)
          (+ (sys:MUL 0.00833333 x5)
             (+ (sys:MUL -0.000198413 x7) (sys:MUL 2.75573e-06 x9)))))))

(define (reduce-angle y)
  (if (> y pi)
      (reduce-angle (- y two-pi))
      (if (< y neg-pi) (reduce-angle (+ y two-pi)) y)))
(define (sin x)
  (let ((y (reduce-angle x)))
    (if (> y half-pi)
        (sin-poly (- pi y))
        (if (< y neg-half-pi) (sys:MUL -1.0 (sin-poly (+ pi y))) (sin-poly y)))))

(define apply
  (case-lambda
    ((fun args)
      (let* ((len (length args)))
        (unless (procedure? fun) (error "Applying to not a procedure:" fun))
        (unless (list? args) (error "Apply to non-list" args))
        ;; sys:APPLY must always be in tail position.
        (sys:APPLY fun args)))
    ((fun . lst)
      (let* ((rlst (reverse lst))
             (unused (unless (list? (car rlst)) (error "Apply to non-list" (car rlst))))
             (firstargs (reverse (cdr rlst)))
             (args (append firstargs (car rlst))))
        (apply fun args)))))

(define (assq obj1 alist1)
  (let loop ((obj obj1) (alist alist1))
    (if (null? alist)
        #f
        (begin (if (eq? (caar alist) obj) (car alist) (loop obj (cdr alist)))))))
(define (assv obj1 alist1)
  (let loop ((obj obj1) (alist alist1))
    (if (null? alist)
        #f
        (begin (if (eqv? (caar alist) obj) (car alist) (loop obj (cdr alist)))))))
(define assoc
  (case-lambda
    ((obj1 alist1 compare)
      (let loop ((obj obj1) (alist alist1))
        (if (null? alist)
            #f
            (begin (if (compare (caar alist) obj) (car alist) (loop obj (cdr alist)))))))
    ((obj alist) (assoc obj alist equal?))))

(define (memv obj list)
  (let loop ((list list))
    (if (null? list) #f (if (eq? obj (car list)) list (loop (cdr list))))))
(define (memq obj list)
  (let loop ((list list))
    (if (null? list) #f (if (eqv? obj (car list)) list (loop (cdr list))))))
(define (member obj list)
  (let loop ((list list))
    (if (null? list) #f (if (equal? obj (car list)) list (loop (cdr list))))))
;;; char
(define (char-downcase c)
  (let ((n (char->integer c)))
    (if (or (< n 65) ; A
           (> n 90)) ; Z
        (integer->char n)
        (integer->char (+ n 32)))))

(define (char-upcase c)
  (let ((n (char->integer c)))
    (if (or (< n 97) ; a
           (> n 122)) ; z
        (integer->char n)
        (integer->char (- n 32)))))

(define (char-whitespace? c)
  (let ((n (char->integer c)))
    (or (eq? n 32) (eq? n 9) (eq? n 12) (eq? n 10) (eq? n 13))))

(define char=? (case-lambda ((a b) (eq? a b)) (rest (comparer eq? rest))))
(define char>?
  (case-lambda
    ((a b) (> (char->integer a) (char->integer b)))
    (rest (comparer char>? rest))))
(define char<?
  (case-lambda
    ((a b) (< (char->integer a) (char->integer b)))
    (rest (comparer (lambda (a b) (char<? a b)) rest))))
(define char>=?
  (case-lambda
    ((a b) (>= (char->integer a) (char->integer b)))
    (rest (comparer (lambda (a b) (char>=? a b)) rest))))
(define char<=?
  (case-lambda
    ((a b) (<= (char->integer a) (char->integer b)))
    (rest (comparer (lambda (a b) (char<=? a b)) rest))))
(define (char-ci=? x y) (char=? (char-downcase x) (char-downcase y)))
(define (char-ci>? x y) (char>? (char-downcase x) (char-downcase y)))
(define (char-ci<? x y) (char<? (char-downcase x) (char-downcase y)))
(define (char-ci>=? x y) (char>=? (char-downcase x) (char-downcase y)))
(define (char-ci<=? x y) (char<=? (char-downcase x) (char-downcase y)))
(define (char-alphabetic? c)
  (let ((n (char->integer c)))
    (cond
      ((< n 65) #f) ; A
      ((> n 122) #f) ; z
      ((> n 96)) ; a-1
      ((< n 91)) ; Z+1
      (else #f))))
(define (char-numeric? c)
  (let ((n (char->integer c)))
    (cond
      ((< n 48) #f) ; 0
      ((> n 57) #f) ; 9
      (else #t))))
(define (char-upper-case? c)
  (let ((n (char->integer c)))
    (cond
      ((< n 65) #f) ; A
      ((> n 90) #f) ; Z
      (else #t))))

(define (char-lower-case? c)
  (let ((n (char->integer c)))
    (cond
      ((< n 97) #f) ; a
      ((> n 122) #f) ; z
      (else #t))))
;;; symbol table

;; This is a bit of a hack: the bitcode compiler will generate a correct
;; symbol table for us consisting of all symbols.  The expander needs to know
;; the symbol, but don't set to '(), so set it to itself.
(define symbol-table symbol-table)
(define (string->symbol string)
  (cond
    ((assoc string symbol-table) => cdr)
    (else
      (let* ((new-name (string-copy string)) (cell (sys:ALLOC (* 8 5) 6)))
        (sys:STORE cell new-name 0)
        (sys:STORE cell 36 1)
        (sys:STORE cell #f 2)
        (sys:STORE cell #f 3)
        (set! symbol-table (cons (cons new-name cell) symbol-table))
        cell))))
;; strings
(define string-copy
  (case-lambda
    ((string) (substring string 0 (string-length string)))
    ((string start) (substring string start (string-length string)))
    ((string start end) (substring string start end))))
(define (str-copy-internal tostr tostart fromstr fromstart fromend)
  (let loop ((frompos fromstart) (topos tostart))
    (if (< frompos fromend)
        (begin
          (string-set! tostr topos (string-ref fromstr frompos))
          (loop (+ frompos 1) (+ topos 1))))))
(define (substring s start end)
  (let ((new (make-string (- end start))))
    (str-copy-internal new 0 s start end)
    new))
(define (string . chars) (list->string chars))
(define (list->string chars)
  (let* ((len (length chars)) (c (make-string len)))
    (let loop ((i 0) (chars chars))
      (if (< i len)
          (begin (string-set! c i (car chars)) (loop (+ i 1) (cdr chars)))))
    c))

(define (string-append2 a b)
  (let* ((lena (string-length a))
         (lenb (string-length b))
         (newstr (make-string (+ lena lenb))))
    (str-copy-internal newstr 0 a 0 lena)
    (str-copy-internal newstr lena b 0 lenb)
    newstr))

(define string-append
  (case-lambda
    ((a b) (string-append2 a b))
    ((a b c d e)
      (string-append2 a (string-append2 b (string-append2 c (string-append2 d e)))))
    (strs
      (let* ((totallen (apply + (map string-length strs)))
             (newstr (make-string totallen)))
        (let loop ((strs strs) (place 0))
          (if (not (null? strs))
              (let* ((cur_str (car strs)) (cur_len (string-length cur_str)))
                (str-copy-internal newstr place (car strs) 0 cur_len)
                (loop (cdr strs) (+ place cur_len)))))
        newstr))))
(define (strcmp eq? f a b eq lt gt)
  (let loop ((pos 0) (rema (string-length a)) (remb (string-length b)))
    (cond
      ((and (= rema 0) (= remb 0)) eq)
      ((= rema 0) lt)
      ((= remb 0) gt)
      ((eq? (string-ref a pos) (string-ref b pos))
        (loop (+ pos 1) (- rema 1) (- remb 1)))
      (else (f (string-ref a pos) (string-ref b pos))))))

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

;; VECTOR
(define vector
  (case-lambda
    ((a) (let ((v (make-vector 1))) (vector-set! v 0 a) v))
    ((a b) (let ((v (make-vector 2))) (vector-set! v 0 a) (vector-set! v 1 b) v))
    ((a b c)
      (let ((v (make-vector 3)))
        (vector-set! v 0 a)
        (vector-set! v 1 b)
        (vector-set! v 2 c)
        v))
    ((a b c d)
      (let ((v (make-vector 4)))
        (vector-set! v 0 a)
        (vector-set! v 1 b)
        (vector-set! v 2 c)
        (vector-set! v 3 d)
        v))
    (vals (list->vector vals))))

;; math
(define (expt num exp)
  (if (> exp 0)
      (let loop ((n 1) (cnt exp)) (if (= cnt 0) n (loop (* num n) (- cnt 1))))
      (let loop ((n 1) (cnt exp)) (if (= cnt 0) n (loop (/ n num) (+ cnt 1))))))

(define (odd? x) (= 1 (modulo x 2)))

(define (even? x) (= 0 (modulo x 2)))
(define min
  (case-lambda
    ((a b)
      (let ((res (if (< a b) a b)))
        (if (or (inexact? a) (inexact? b)) (inexact res) res)))
    (args
      (let loop ((args args))
        (if (eq? (length args) 1)
            (car args)
            (let* ((a (car args))
                   (b (cadr args))
                   (m (if (> a b) b a))
                   (i (if (or (inexact? a) (inexact? b)) (inexact m) m)))
              (loop (cons i (cddr args)))))))))
(define max
  (case-lambda
    ((a b)
      (let ((res (if (> a b) a b)))
        (if (or (inexact? a) (inexact? b)) (inexact res) res)))
    (args
      (let loop ((args args))
        (if (eq? (length args) 1)
            (car args)
            (let* ((a (car args))
                   (b (cadr args))
                   (m (if (< a b) b a))
                   (i (if (or (inexact? a) (inexact? b)) (inexact m) m)))
              (loop (cons i (cddr args)))))))))

(define gcd
  (case-lambda
    (() 0)
    ((a) a)
    ((a b) (if (= b 0) (abs a) (gcd b (remainder a b))))
    (args
      (let lp ((x (car args)) (ls (cdr args)))
        (if (null? ls) x (lp (gcd x (car ls)) (cdr ls)))))))

(define lcm
  (case-lambda
    (() 1)
    ((a) a)
    ((a b) (abs (quotient (* a b) (gcd a b))))
    (args
      (let lp ((x (car args)) (ls (cdr args)))
        (if (null? ls) x (lp (lcm x (car ls)) (cdr ls)))))))

;;;;;;;;;;;;;;;;;;; number->string
(define number->string
  (case-lambda
    ((num) (number->string num 10))
    ((num base)
      ;;(unless (and (number? num) (fixnum? base) (<= 1 base 16)) (error "bad number->string" num))
      (let* ((buflen 100) (buffer (make-string buflen)))
        (cond
          ((flonum? num) (display "Error flonum->string") (/ 1 0))
          ((bignum? num) (sys:FOREIGN_CALL '(string "bignum_string" (gc_obj)) num))
          ;; ((ratnum? num) (error "numbratnum->str" num))
          ;; ((compnum? num) (string-append
          ;; 		     (number->string (real-part num))
          ;; 		     (if (not (or (negative? (imag-part num))
          ;; 				  (nan? (imag-part num))
          ;; 				  (infinite? (imag-part num))))
          ;; 			 "+" "")
          ;; 		     (number->string (imag-part num)) "i"))
          ((eq? num 0) "0")
          (else
            (let ((neg (negative? num)))
              (let loop ((p buflen) (n (if neg (- 0 num) num)))
                (cond
                  ((eq? n 0)
                    (if neg (begin (set! p (- p 1)) (string-set! buffer p #\-)))
                    (substring buffer p buflen))
                  (else
                    (let ((q (quotient n base)) (r (modulo n base)) (p (- p 1)))
                      (string-set! buffer p (integer->char (+ r (if (>= r 10) 55 48))))
                      (loop p q))))))))))))

(include "str2num.scm")
;;; call/cc

(define (call-with-current-continuation thunk) (sys:CALLCC thunk))

(define (call/cc thunk) (call-with-current-continuation thunk))

(define (error . msg)
  (sys:WRITE "ERROR:")
  (sys:WRITE msg)
  (sys:WRITE "\n")
  (/ 1 0))

;;;;;; Records
(define (record-set! record index value)
  (unless (record? record) (error "record-set!: not a record" record))
  (sys:STORE record value (+ index 1)))
(define (record-ref record index)
  (unless (record? record) (error "record-ref: not a record" record))
  (sys:LOAD record (+ index 1)))
(define (make-record sz)
  (let ((rec (sys:ALLOC (+ (* 8 (+ 1 sz)) 8) 49)))
    (sys:STORE rec (+ sz 1) 0)
    (do ((i 0 (+ i 1))) ((= i sz) rec) (record-set! rec i #f))))
(define (record? p) (sys:GUARD p 49))

(define :record-type (make-record 3))
(record-set! :record-type 0 :record-type) ; Its type is itself.
(record-set! :record-type 1 ':record-type)
(record-set! :record-type 2 '(name field-tags))

(define (make-record-type name field-tags)
  (let ((rec (make-record 3)))
    (record-set! rec 0 :record-type)
    (record-set! rec 1 name)
    (record-set! rec 2 field-tags)
    rec))

(define (record-type-name record-type) (record-ref record-type 1))

(define (record-type-field-tags record-type) (record-ref record-type 2))

(define (field-index type tag)
  (let loop ((i 1) (tags (record-type-field-tags type)))
    (cond
      ((null? tags) (error "record type has no such field" type tag))
      ((eq? tag (car tags)) i)
      (else (loop (+ i 1) (cdr tags))))))
(define (record-constructor type tags)
  (let ((size (length (record-type-field-tags type)))
        (arg-count (length tags))
        (indexes (map (lambda (tag) (field-index type tag)) tags)))
    (lambda args
      (if (= (length args) arg-count)
          (let ((new (make-record (+ size 1))))
            (record-set! new 0 type)
            (for-each (lambda (arg i) (record-set! new i arg)) args indexes)
            new)
          (error "wrong number of arguments to constructor" type args)))))

;;;;;; Port ops
(define-record-type port (make-port fd peek input buf pos len sbuf) port?
  (fd port-fd)
  (peek port-peek port-peek-set!)
  (input port-input?)
  (buf port-buf port-buf-set!)
  (pos port-pos port-pos-set!)
  (len port-len port-len-set!)
  (sbuf port-sbuf port-sbuf-set!))

(define port-buffer-size 4096)
(define (make-input-port fd)
  (make-port fd #f #t (make-string port-buffer-size) 0 0 #f))
(define (make-output-port fd)
  (make-port fd #f #f (make-string port-buffer-size) 0 0 #f))
(define (make-string-output-port) (make-port -1 #f #f #f 0 0 ""))

(define display
  (case-lambda
    ((x) (display x (current-output-port)))
    ((x port)
      (cond
        ((flonum? x)
          (display (sys:FOREIGN_CALL '(string "flonum_string" (double)) x) port))
        ((number? x) (display (number->string x) port))
        ((char? x) (write-char x port))
        ((vector? x)
          (display "#(" port)
          (do ((i 0 (+ i 1)))
               ((= i (vector-length x)))
               (unless (= i 0) (write-char #\space port))
               (display (vector-ref x i) port))
          (write-char #\) port))
        ((pair? x)
          (write-char #\( port)
          (let loop ((cur x))
            (if (pair? (cdr cur))
                (begin (display (car cur) port) (write-char #\space port) (loop (cdr cur)))
                (begin
                  (display (car cur) port)
                  (unless (eq? '() (cdr cur)) (display " . " port) (display (cdr cur) port)))))
          (write-char #\) port))
        ((symbol? x) (display (symbol->string x) port))
        ;; TODO lookup name
        ((procedure? x)
          (display "#<procedure " port)
          (display (sys:LOAD (sys:LOAD x 1) 0) port)
          (display ">" port))
        ((eq? x #t) (display "#t" port))
        ((eq? x #f) (display "#f" port))
        ((eq? x '()) (display "()" port))
        ((eof-object? x) (display "#<eof>" port))
        ((port? x) (display "#<port>" port))
        ((record? x) (display "#<record>" port))
        ((string? x)
          (do ((i 0 (+ i 1)))
               ((= i (string-length x)))
               (write-char (string-ref x i) port)))
        (else (error "Bad type in display: " x))))))

(define newline
  (case-lambda
    (() (newline (current-output-port)))
    ((port) (display #\newline port))))

(define input-port? port-input?)
(define (output-port? port) (and (port? port) (not (port-input? port))))

(define *current-input-port* (make-input-port 0))
(define (current-input-port) *current-input-port*)
(define *current-output-port* (make-output-port 1))
(define (current-output-port) *current-output-port*)
(define *current-error-port* (make-output-port 2))
(define (current-error-port) *current-error-port*)

(define (c-open pathname read)
  (sys:FOREIGN_CALL '(int32 "scm_open" (string uint8)) pathname read))

(define (c-close fd) (sys:FOREIGN_CALL '(int32 "close" (int32)) fd))

(define (c-write fd data len)
  (sys:FOREIGN_CALL '(int64 "write" (int32 string uint64)) fd data len))

(define (c-read fd buf cnt)
  (sys:FOREIGN_CALL '(int64 "read" (int32 string uint64)) fd buf cnt))

(define (delete-file filename)
  (let ((res (sys:FOREIGN_CALL '(int32 "unlink" (string)) filename)))
    (unless (= 0 res) (error "Bad unlink:" filename res))))

(define (file-exists? filename)
  (= 0 (sys:FOREIGN_CALL '(int32 "access" (string int32)) filename 0)))

(define (open-input-file file)
  (let ((fd (c-open file 1)))
    (when (< fd 0) (error "open-input-file error:" file))
    (make-input-port fd)))
(define (open-output-file file)
  (let ((fd (c-open file 0)))
    (when (< fd 0) (error "open-output-file error:" file))
    (make-output-port fd)))
(define (write-all fd data len)
  (let loop ((off 0))
    (if (< off len)
        (let* ((buf (if (= off 0) data (substring data off len)))
               (cnt (c-write fd buf (- len off))))
          (if (<= cnt 0) (error "write error" cnt) (loop (+ off cnt))))
        #t)))
(define (flush-port-write-buffer port)
  (let ((len (port-len port)))
    (if (> len 0)
        (begin
          (write-all (port-fd port) (port-buf port) len)
          (port-len-set! port 0)
          #t)
        #t)))
(define (close-port port)
  (if (>= (port-fd port) 0)
      (begin
        (if (not (port-input? port)) (flush-port-write-buffer port))
        (c-close (port-fd port)))
      #t))
(define close-output-port close-port)
(define close-input-port close-port)
(define-record-type eof-object (make-eof-object) eof-object?)
(define (read-from-port-buffer port)
  (if (not (port-input? port))
      (error "read-char: not an input port" port)
      (let ((pos (port-pos port)) (len (port-len port)) (buf (port-buf port)))
        (if (< pos len)
            (let ((c (string-ref buf pos))) (port-pos-set! port (+ pos 1)) c)
            (let ((cnt (c-read (port-fd port) buf port-buffer-size)))
              (if (> cnt 0)
                  (begin (port-pos-set! port 1) (port-len-set! port cnt) (string-ref buf 0))
                  (make-eof-object)))))))
(define peek-char
  (case-lambda
    (() (peek-char (current-input-port)))
    ((port)
      (cond
        ((port-peek port))
        (else
          (let ((c (read-from-port-buffer port)))
            (if (eof-object? c) c (begin (port-peek-set! port c) c))))))))

(define read-char
  (case-lambda
    (() (read-char (current-input-port)))
    ((port)
      (cond
        ((port-peek port) => (lambda (x) (port-peek-set! port #f) x))
        (else (read-from-port-buffer port))))))
(define read-line
  (case-lambda
    (() (read-line (current-input-port)))
    ((port)
      (let loop ((chars '()))
        (let ((c (read-char port)))
          (cond
            ((eof-object? c) (if (null? chars) c (list->string (reverse chars))))
            ((char=? c #\newline) (list->string (reverse chars)))
            ((char=? c #\return)
              (let ((next (peek-char port)))
                (if (and (char? next) (char=? #\newline next)) (read-char port)))
              (list->string (reverse chars)))
            (else (loop (cons c chars)))))))))
(define (write-char char port)
  (cond
    ((port-sbuf port)
      (port-sbuf-set! port (string-append (port-sbuf port) (make-string 1 char)))
      #t)
    ((not (port-input? port))
      (let ((len (port-len port)))
        (if (= len port-buffer-size)
            (begin
              (flush-port-write-buffer port)
              (string-set! (port-buf port) 0 char)
              (port-len-set! port 1)
              #t)
            (begin
              (string-set! (port-buf port) len char)
              (port-len-set! port (+ len 1))
              #t))))
    (else (error "write-char: not an output port" port))))
(define write-string
  (case-lambda
    ((str) (write-string str (current-output-port)))
    ((str port) (write-string str port 0 (string-length str)))
    ((str port start) (write-string str port start (string-length str)))
    ((str port start end)
      (let loop ((i start))
        (if (< i end) (begin (write-char (string-ref str i) port) (loop (+ i 1))) #t)))))

(define (string->list str)
  (let ((n (string-length str)))
    (let loop ((i (- n 1)) (lst '()))
      (if (< i 0) lst (loop (- i 1) (cons (string-ref str i) lst))))))
(define write
  (case-lambda
    ((arg) (write arg (current-output-port)))
    ((arg port)
      (cond
        ((null? arg) (display "()" port))
        ((pair? arg)
          (display "(" port)
          (let loop ((arg arg))
            (if (not (pair? arg))
                (begin (display ". " port) (write arg port))
                (begin
                  (write (car arg) port)
                  (if (not (null? (cdr arg))) (begin (display " " port) (loop (cdr arg)))))))
          (display ")" port))
        ((vector? arg) (display "#" port) (write (vector->list arg) port))
        ((char? arg)
          (cond
            ((char=? #\newline arg) (display "#\\newline" port))
            ((char=? #\tab arg) (display "#\\tab" port))
            ((char=? #\space arg) (display "#\\space" port))
            ((char=? #\return arg) (display "#\\return" port))
            (else (display "#\\" port) (display arg port))))
        ((string? arg)
          (display "\"" port)
          (for-each (lambda (chr)
                      (cond
                        ((char=? #\" chr) (display "\\\"" port))
                        ((char=? #\\ chr) (display "\\\\" port))
                        (else (display chr port))))
                    (string->list arg))
          (display "\"" port))
        (else (display arg port))))))

(define (open-output-string) (make-string-output-port))
(define (get-output-string port) (port-sbuf port))

(define (call-with-input-file file l)
  (let* ((p (open-input-file file)) (res (l p))) (close-input-port p) res))

(define (call-with-output-file file l)
  (let* ((p (open-output-file file)) (res (l p))) (close-output-port p) res))

(define flush-output-port
  (case-lambda
    (() (flush-output-port (current-output-port)))
    ((port)
      (cond
        ((port-sbuf port) #t)
        ((not (port-input? port)) (flush-port-write-buffer port))
        (else #t)))))

;; TIME

(define (jiffies-per-second) 1000000000)

(define (current-jiffy)
  (call-with-input-file "/proc/uptime" (lambda (port) (read port))))
(define (current-second)
  (call-with-input-file "/proc/uptime" (lambda (port) (read port))))

(define read-buf (make-string 1000))
(define read
  (case-lambda
    (() (read (current-input-port)))
    ((port)
      (define line 1)
      (define (read2 port)
        (define (read-to-delimited)
          (let loop ((res 0) (c (peek-char port)))
            (if (eof-object? c)
                (if (not (= 0 res)) (substring read-buf 0 res) c)
                (case c
                  ((#\( #\) #\" #\| #\newline #\return #\space #\tab #\;)
                    (substring read-buf 0 res))
                  (else
                    (string-set! read-buf res (read-char port))
                    (loop (+ res 1) (peek-char port)))))))
        (define (skip-whitespace)
          (let loop ()
            (let ((c (peek-char port)))
              (cond
                ((eof-object? c) c)
                ((char=? #\newline c) (set! line (+ 1 line)) (read-char port) (loop))
                ((char-whitespace? c) (read-char port) (loop))))))
        (define (skip-whitespace-and-comments)
          (let loop ()
            (let ((c (peek-char port)))
              (cond
                ((eof-object? c) c)
                ((char=? #\newline c) (set! line (+ 1 line)) (read-char port) (loop))
                ((char-whitespace? c) (read-char port) (loop))
                ((char=? #\; c) (skip-line) (loop))))))
        (define (skip-line)
          (let loop ()
            (let ((c (read-char port)))
              (if (eof-object? c) c (if (char=? c #\newline) (set! line (+ 1 line)) (loop))))))
        (define (read-escape)
          (let ((c (read-char port)))
            (if (eof-object? c) (error "Incomplete escape sequence"))
            (case c
              ((#\a) #\alarm)
              ((#\n) #\newline)
              ((#\r) #\return)
              ((#\t) #\tab)
              ((#\b) #\backspace)
              ((#\tab #\space) (skip-line) (skip-whitespace) #f)
              ((#\newline) (skip-whitespace) #f)
              ((#\x #\X)
                (let* ((delim (read-to-delimited))
                       (ch (string->number delim 16))
                       (next (read-char port)))
                  (if (not (eq? #\; next))
                      (error "Invalid hex string escape")
                      (integer->char ch))))
              (else c))))
        (define (read-delimited term)
          (let loop ((res 0) (c (read-char port)))
            (cond
              ((eof-object? c)
                (error "incomplete object:" (substring read-buf 0 res) "line: " line))
              ((char=? #\\ c)
                (let ((es (read-escape)))
                  (if es
                      (begin (string-set! read-buf res es) (loop (+ 1 res) (read-char port)))
                      (loop res (read-char port)))))
              ((char=? term c) (substring read-buf 0 res))
              (else (string-set! read-buf res c) (loop (+ 1 res) (read-char port))))))
        (define (lower-case string)
          (do ((i 0 (+ i 1)))
               ((= i (string-length string)) string)
               (string-set! string i (char-downcase (string-ref string i)))))
        (define (read-list)
          (define line-start line)
          (let loop ((res '()))
            (skip-whitespace-and-comments)
            (let ((c (peek-char port)))
              (cond
                ((eof-object? c)
                  (error "EOF found while parsing list starting on line "
                         line-start
                         " and ending "
                         line))
                ((char=? c #\)) (read-char port) (reverse res))
                ((char=? c #\.)
                  (let ((token (read-to-delimited)))
                    (if (= 1 (string-length token))
                        (let ((fin (read-one)))
                          (skip-whitespace-and-comments)
                          (if (not (eq? #\) (read-char port)))
                              (error "Invalid dotted list")
                              (append (reverse res) fin)))
                        (loop (cons (cond
                                      ((string->number token) => (lambda (num) num))
                                      (else (string->symbol (lower-case token))))
                                    res)))))
                (else (loop (cons (read-one) res)))))))
        (define named-chars
          '(("tab" . #\tab)
            ("space" . #\space)
            ("return" . #\return)
            ("newline" . #\newline)
            ("alarm" . #\alarm)
            ("backspace" . #\backspace)
            ("delete" . #\delete)
            ;("escape" . #\escape)
            ;		      ("null" . #\null)
          ))
        (define delims '(#\( #\) #\; #\| #\" #\space))
        (define (do-read-char)
          (let ((ch (peek-char port)))
            (if (memv ch delims)
                (read-char port)
                (let ((token (read-to-delimited)))
                  (cond
                    ((= 1 (string-length token)) (string-ref token 0))
                    ((assoc token named-chars) => cdr)
                    (else (error "Error invalid char: " token)))))))
        (define (skip-comment)
          (let loop ((depth 0))
            (case (read-char port)
              ((#\#) (loop (if (char=? #\| (peek-char port)) (+ 1 depth) depth)))
              ((#\|)
                (if (char=? #\# (peek-char port))
                    (if (= 0 depth) (read-char port) (loop (- depth 1)))
                    (loop depth)))
              ((#\newline) (set! line (+ 1 line)) (loop depth))
              (else
                (if (eof-object? (peek-char port))
                    (error "unterminated comment")
                    (loop depth))))))
        (define (read-hash)
          (let ((c (peek-char port)))
            (case c
              ((#\|) (skip-comment))
              ((#\;) (read-char port) (read-one) (read-one))
              ((#\() (read-char port) (list->vector (read-list)))
              ((#\\) (read-char port) (do-read-char))
              ((#\t #\T #\f #\F)
                (let ((v (lower-case (read-to-delimited))))
                  (cond
                    ((equal? "f" v) #f)
                    ((equal? "t" v) #t)
                    ((equal? "true" v) #t)
                    ((equal? "false" v) #f)
                    (else (error "Can't parse hash token:" v)))))
              ((#\b #\B #\o #\O #\d #\D #\x #\X #\i #\I #\e #\E)
                (string->number (string-append "#" (read-to-delimited))))
              ((#\u)
                (read-char port)
                (if (not (char=? #\8 (peek-char port)))
                    (error "Not a bytevector:" (peek-char port))
                    (read-char port))
                (let ((ls (read-one)))
                  (if (not (list? ls)) (error "Not a bytevector list:" ls) ls)))
              (else (error "Unknown hash: " c)))))
        (define (read-one)
          (skip-whitespace)
          (let ((c (peek-char port)))
            (case (peek-char port)
              ((#\#) (read-char port) (read-hash))
              ((#\() (read-char port) (read-list))
              ((#\)) (read-char port) (error "Extra list terminator found"))
              ((#\") (read-char port) (read-delimited #\"))
              ((#\;) (read-char port) (skip-line) (read-one))
              ((#\|) (read-char port) (string->symbol (read-delimited #\|)))
              ((#\') (read-char port) (list 'quote (read-one)))
              ((#\`) (read-char port) (list 'quasiquote (read-one)))
              ((#\,)
                (read-char port)
                (case (peek-char port)
                  ((#\@) (read-char port) (list 'unquote-splicing (read-one)))
                  (else (list 'unquote (read-one)))))
              (else
                (let ((token (read-to-delimited)))
                  (cond
                    ((eof-object? token) token)
                    ((string->number token) => (lambda (num) num))
                    (else (string->symbol (lower-case token)))))))))
        (read-one))
      (read2 port))))
;; flonum
;;;;;;;;;
(define (sin d) (sys:FOREIGN_CALL '(double "sin" (double)) (inexact d)))
(define (cos d) (sys:FOREIGN_CALL '(double "cos" (double)) (inexact d)))
(define (asin d) (sys:FOREIGN_CALL '(double "asin" (double)) (inexact d)))
(define (acos d) (sys:FOREIGN_CALL '(double "acos" (double)) (inexact d)))
(define (sqrt d) (sys:FOREIGN_CALL '(double "sqrt" (double)) (inexact d)))
(define (atan d) (sys:FOREIGN_CALL '(double "atan" (double)) (inexact d)))
(define (tan d) (sys:FOREIGN_CALL '(double "tan" (double)) (inexact d)))
(define (round d)
  (let* ((d (inexact d)) (rounded (sys:FOREIGN_CALL '(double "round" (double)) d)))
    ;; Round to even, towards zero.
    (if (and (= 0.5 (sys:FOREIGN_CALL '(double "fabs" (double)) (- d rounded)))
             (not (= 0.0 (sys:FOREIGN_CALL '(double "fmod" (double double)) rounded 2.0))))
        (+ rounded (if (> d 0) -1 1))
        rounded)))
(define (ceiling x) (sys:FOREIGN_CALL '(double "ceil" (double)) (inexact x)))
(define (log x) (sys:FOREIGN_CALL '(double "log" (double)) (inexact x)))

;; values

(define (call-with-values producer consumer) (apply consumer (producer)))

(define values
  (case-lambda
    ((a) a)
    ((a b) (cons a (cons b '())))
    ((a b c) (cons a (cons b (cons c '()))))
    (rest rest)))
;; bytevectors

(define make-bytevector make-string)
(define (bytevector-u8-set! bv i val) (string-set! bv i (integer->char val)))
(define (utf8->string v) v)
(define (string->utf8 v) v)

;; process-context
(define (exit int)
  (flush-output-port)
  (flush-output-port (current-error-port))
  (sys:HALT))
