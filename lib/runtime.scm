(import (only (scheme base)
              or
              and
              define
              unless
              cond
              include
              let
              let*
              let-values
              if
              begin
              quote
              quasiquote
              unquote
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
              define-record-type
              parameterize) (scheme case-lambda) (prefix (hawk sys) sys:))

(define (truncate x) (sys:TRUNCATE x))
(define (inexact x) (sys:INEXACT x))
(define (exact x) (sys:EXACT x))
(define (char->integer x) (sys:CHAR_INTEGER x))
(define (integer->char x) (sys:INTEGER_CHAR x))
(define (exact->inexact x) (sys:INEXACT x))
(define (inexact->exact x) (sys:EXACT x))

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
(define (make-rectangular real imag) (sys:RECT real imag))
(define (real-part z) (if (compnum? z) (sys:LOAD z 0) z))
(define (imag-part z) (if (compnum? z) (sys:LOAD z 1) 0))
(define (square x) (* x x))
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

(define /
  (case-lambda
    ((a) (sys:DIV 1 a))
    ((a b) (sys:DIV a b))
    ((a . rest) (sys:DIV a (apply * rest)))))

(define (comparer f args)
  (let loop ((args args))
    (if (and (pair? args) (pair? (cdr args)))
        (if (f (car args) (cadr args)) (loop (cdr args)) #f)
        #t)))

(define boolean=? (case-lambda ((a b) (eq? a b)) (rest (comparer eq? rest))))
(define symbol=? (case-lambda ((a b) (eq? a b)) (rest (comparer eq? rest))))
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
    ((a b) (sys:NUMEQ a b))
    (rest (comparer (lambda (a b) (sys:NUMEQ a b)) rest))))

(define (eq? a b) (sys:EQ a b))

(define (list? x) (sys:FOREIGN_CALL '(gc_obj "SCM_LISTP" (gc_obj)) x))

(define (length a) (sys:FOREIGN_CALL '(gc_obj "SCM_LENGTH" (gc_obj)) a))

(define (assq obj1 alist1)
  (sys:FOREIGN_CALL '(gc_obj "SCM_ASSQ" (gc_obj gc_obj)) obj1 alist1))
(define (assv obj1 alist1)
  (sys:FOREIGN_CALL '(gc_obj "SCM_ASSV" (gc_obj gc_obj)) obj1 alist1))

(define for-each
  (case-lambda
    ((proc lst)
      (unless (list? lst) (error "circular for-each"))
      (let loop ((proc proc) (lst lst))
        (unless (null? lst) (proc (car lst)) (loop proc (cdr lst)))))
    ((proc lst1 lst2)
      (unless (or (list? lst1) (list? lst2)) (error "circular for-each"))
      (let loop ((proc proc) (lst1 lst1) (lst2 lst2))
        (if (and (not (null? lst1)) (not (null? lst2)))
            (begin (proc (car lst1) (car lst2)) (loop proc (cdr lst1) (cdr lst2))))))
    ((proc . lsts)
      ;(unless (any list? lsts) (error "circular for-each"))
      (let loop ((lsts lsts))
        (let ((hds
                 (let loop2 ((lsts lsts))
                   (if (null? lsts)
                       '()
                       (let ((x (car lsts)))
                         (and (not (null? x))
                              (let ((r (loop2 (cdr lsts)))) (and r (cons (car x) r)))))))))
          (if hds
              (begin
                (apply proc hds)
                (loop (let loop3 ((lsts lsts))
                        (if (null? lsts) '() (cons (cdr (car lsts)) (loop3 (cdr lsts)))))))))))))

(define string-for-each
  (case-lambda
    ((proc str)
      (do ((len (string-length str)) (i 0 (+ i 1)) (pos 0 (+ pos 1)))
           ((= i len))
           (proc (string-ref str pos))))
    ((proc . strs)
      (do ((len (apply min (map string-length strs))) (i 0 (+ i 1)))
           ((= i len))
           (apply proc (map (lambda (x) (string-ref x i)) strs))))))

(define (vector-for-each proc . vecs)
  (do ((len (apply min (map vector-length vecs))) (i 0 (+ i 1)))
       ((= i len))
       (apply proc (map (lambda (x) (vector-ref x i)) vecs))))

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
             (q (quotient size 8))
             (r (modulo size 8))
             (alloc_size (if (= r 0) (* q 8) (* (+ q 1) 8)))
             (str (sys:ALLOC alloc_size 9)))
        (sys:STORE str len 0)
        (string-set! str len #\null)
        (when c (do ((i 0 (+ i 1))) ((= i len)) (string-set! str i c)))
        str))))

(define (cons a b) (sys:CONS a b))
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
(define (ratnum? a) (sys:GUARD a 25))
(define (compnum? a) (sys:GUARD a 65))
(define (numerator a)
  (cond
    ((inexact? a) (inexact (numerator (exact a))))
    ((ratnum? a) (sys:LOAD a 0))
    (else a)))

(define (denominator x)
  (cond
    ((inexact? x) (inexact (denominator (exact x))))
    ((ratnum? x) (sys:LOAD x 1))
    (else 1)))
(define (number? x)
  (or (fixnum? x) (flonum? x) (bignum? x) (ratnum? x) (compnum? x)))
(define complex? number?)
(define (real? x) (and (number? x) (not (compnum? x))))
(define (rational? x)
  (and (number? x)
       (not (compnum? x))
       (not (and (flonum? x)
                 (or (sys:FOREIGN_CALL '(bool "SCM_ISNAN" (double)) x)
                    (sys:FOREIGN_CALL '(bool "SCM_ISINF" (double)) x))))))
(define (integer? x)
  (or (fixnum? x)
     (bignum? x)
     (and (ratnum? x) (= 1 (denominator x)))
     (and (flonum? x)
          (not (nan? x))
          (not (infinite? x))
          (= 1 (denominator (exact x))))))
(define (nan? x)
  (or (and (flonum? x) (sys:FOREIGN_CALL '(bool "SCM_ISNAN" (double)) x))
     (and (compnum? x) (or (nan? (real-part x)) (nan? (imag-part x))))))
(define (infinite? x)
  (or (and (flonum? x) (sys:FOREIGN_CALL '(bool "SCM_ISINF" (double)) x))
     (and (compnum? x) (or (infinite? (real-part x)) (infinite? (imag-part x))))))
(define (finite? num) (or (not (number? num)) (not (infinite? num))))
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
(define (undefined? a) (sys:GUARD a 36))
(define (zero? z) (= z 0))
(define (negative? a) (< a 0))
(define (positive? a) (> a 0))
(define (abs p) (if (negative? p) (- p) p))
(define (list-tail lst k)
  (let loop ((lst lst) (k k)) (if (> k 0) (loop (cdr lst) (- k 1)) lst)))
(define make-list
  (case-lambda
    ((k) (make-list k '()))
    ((k fill) (if (= k 0) '() (cons fill (make-list (- k 1) fill))))))
(define (list . x) x)
(define (set-car! a b) (sys:STORE a b 0))
(define (set-cdr! a b) (sys:STORE a b 1))
(define (string-length a) (sys:LOAD a 0))
(define (string-map proc . strs)
  (let* ((len (apply min (map string-length strs))) (str (make-string len)))
    (do ((i 0 (+ i 1)))
         ((= i len) str)
         (string-set! str i (apply proc (map (lambda (x) (string-ref x i)) strs))))))
(define (car a) (unless (pair? a) (error "CAR: bad load:" a)) (sys:CAR a))
(define (cdr a) (unless (pair? a) (error "CDR: bad load:" a)) (sys:CDR a))
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
(define (list-set! list k obj)
  (do ((list list (cdr list)) (k k (- k 1)) (obj obj))
       ((= k 0) (set-car! list obj))))
(define (list-copy lst)
  (if (pair? lst) (cons (car lst) (list-copy (cdr lst))) lst))
(define (vector-length vec) (sys:LOAD vec 0))
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
        (if (eq? init 0) vec (vector-init vec init 0 len))))))
(define (vector-ref vec idx)
  (unless (< idx (vector-length vec)) (error "Invalid vector index"))
  (sys:LOAD vec (+ 1 idx)))
(define (vector-set! vec idx val)
  (unless (< idx (vector-length vec)) (error "Invalid vector index"))
  (sys:STORE vec val (+ 1 idx)))
(define vector->list
  (case-lambda
    ((vec) (vector->list vec 0 (vector-length vec)))
    ((vec start) (vector->list vec start (vector-length vec)))
    ((vec start end)
      (unless (or (< -1 start (vector-length vec)) (= start end))
        (error "Bad start vector->list" start (vector-length vec)))
      (unless (<= 0 end (vector-length vec))
        (error "Bad end vector->list" end)
        (vector-length vec))
      (when (> start end) (error "Bad end vector->list" end))
      (let loop ((l (- end 1)) (lst '()))
        (if (not (< l start)) (loop (- l 1) (cons (vector-ref vec l) lst)) lst)))))
(define string->vector
  (case-lambda
    ((string) (string->vector string 0 (string-length string)))
    ((string start) (string->vector string start (string-length string)))
    ((string start end)
      (unless (fixnum? start) (error "string->vector" start))
      (unless (or (< -1 start (string-length string)) (= start end))
        (error "Bad start string->vector" start))
      (unless (<= 0 end (string-length string))
        (error "Bad end string->vector" end))
      (when (> start end) (error "Bad end string->vector" end))
      (do ((v (make-vector (- end start))) (i start (+ i 1)) (vpos 0 (+ vpos 1)))
           ((= i end) v)
           (vector-set! v vpos (string-ref string i))))))

(define vector->string
  (case-lambda
    ((vec) (vector->string vec 0 (vector-length vec)))
    ((vec start) (vector->string vec start (vector-length vec)))
    ((vec start end)
      (unless (and (fixnum? start) (fixnum? end)) (error "vector->string" start))
      (unless (or (< -1 start (vector-length vec)) (= start end))
        (error "Bad start vector->string" start))
      (unless (<= 0 end (vector-length vec)) (error "Bad end vector->string" end))
      (when (> start end) (error "Bad end vector->string" end))
      (do ((str (make-string (- end start))) (i start (+ i 1)) (spos 0 (+ spos 1)))
           ((= i end) str)
           (string-set! str spos (vector-ref vec i))))))
(define vector-copy
  (case-lambda
    ((vec) (vector-copy vec 0 (vector-length vec)))
    ((vec start) (vector-copy vec start (vector-length vec)))
    ((vec start end)
      (unless (and (fixnum? start) (fixnum? end)) (error "vector-copy" start))
      (unless (or (< -1 start (vector-length vec)) (= start end))
        (error "Bad start vector-copy" start))
      (unless (<= 0 end (vector-length vec)) (error "Bad end vector-copy" end))
      (when (> start end) (error "Bad end vector-copy" end))
      (do ((v (make-vector (- end start))) (from start (+ from 1)) (to 0 (+ to 1)))
           ((= from end) v)
           (vector-set! v to (vector-ref vec from))))))
(define (vector-append . vecs)
  (let ((v (make-vector (apply + (map vector-length vecs)))))
    (let loop ((pos 0) (vecs vecs))
      (when (pair? vecs)
        (vector-copy! v pos (car vecs))
        (loop (+ pos (vector-length (car vecs))) (cdr vecs))))
    v))

(define vector-copy!
  (case-lambda
    ((to at from) (vector-copy! to at from 0 (vector-length from)))
    ((to at from start) (vector-copy! to at from start (vector-length from)))
    ((to at from start end)
      (unless (and (fixnum? start) (fixnum? end) (fixnum? at))
        (error "vector-copy!" start))
      (unless (or (< -1 start (vector-length from)) (= start end))
        (error "Bad start vector-copy!" start))
      (unless (<= 0 end (vector-length from)) (error "Bad end vector-copy!" end))
      (when (> start end) (error "Bad end vector-copy!" end))
      (if (>= start at)
          (do ((i start (+ i 1)) (out at (+ out 1)))
               ((= i end) to)
               (vector-set! to out (vector-ref from i)))
          (do ((in end (- in 1)) (out (+ at (- end start)) (- out 1)))
               ((= in start) to)
               (vector-set! to (- out 1) (vector-ref from (- in 1))))))))

(define vector-fill!
  (case-lambda
    ((vec fill) (vector-fill! vec fill 0 (vector-length vec)))
    ((vec fill start) (vector-fill! vec fill start (vector-length vec)))
    ((vec fill start end)
      (unless (fixnum? start) (error "vector-fill!" start))
      (unless (or (< -1 start (vector-length vec)) (= start end))
        (error "Bad start vector-fill!" start))
      (unless (<= 0 end (vector-length vec)) (error "Bad end vector-fill!" end))
      (when (> start end) (error "Bad end vector-fill!" end))
      (do ((i start (+ i 1))) ((= i end)) (vector-set! vec i fill))
      vec)))
(define (list->vector lst)
  (let* ((len (length lst)) (v (make-vector len 0)))
    (do ((i 0 (+ i 1)) (p lst (cdr p))) ((= i len) v) (vector-set! v i (car p)))))
(define (vector-map proc . vecs)
  (let* ((len (apply min (map vector-length vecs))) (vec (make-vector len)))
    (do ((i 0 (+ i 1)))
         ((= i len) vec)
         (vector-set! vec i (apply proc (map (lambda (x) (vector-ref x i)) vecs))))))

(define apply
  (case-lambda
    ((fun args)
      (define-syntax apply-list
         (syntax-rules ()
           ((apply-list fun args (arg ...))
            (let ((p args)) (apply-list-step fun p () (arg ...))))))

      (define-syntax apply-list-step
         (syntax-rules ()
           ((apply-list-step fun p (arg ...) ()) (fun arg ...))
           ((apply-list-step fun p (arg ...) (next rest ...))
            (let ((next (car p)) (tail (cdr p)))
              (apply-list-step fun tail (arg ... next) (rest ...))))))

      (unless (procedure? fun) (error "Applying to not a procedure:" fun))
      (unless (list? args) (error "Apply to non-list" fun args))
      (let* ((len (length args)))
        (case len
          ((0) (apply-list fun args ()))
          ((1) (apply-list fun args (a)))
          ((2) (apply-list fun args (a b)))
          ((3) (apply-list fun args (a b c)))
          ((4) (apply-list fun args (a b c d)))
          ((5) (apply-list fun args (a b c d e)))
          ((6) (apply-list fun args (a b c d e f)))
          ((7) (apply-list fun args (a b c d e f g)))
          ((8) (apply-list fun args (a b c d e f g h)))
          ((9) (apply-list fun args (a b c d e f g h i)))
          ((10) (apply-list fun args (a b c d e f g h i j)))
          ((11) (apply-list fun args (a b c d e f g h i j k)))
          ((12) (apply-list fun args (a b c d e f g h i j k l)))
          ;; sys:APPLY must always be in tail position.
          (else (sys:APPLY fun args)))))
    ((fun . lst)
      (let* ((rlst (reverse lst))
             (unused (unless (list? (car rlst)) (error "Apply to non-list" (car rlst))))
             (firstargs (reverse (cdr rlst)))
             (args (append firstargs (car rlst))))
        (apply fun args)))))

;; (define (assq obj1 alist1)
;;   (let loop ((obj obj1) (alist alist1))
;;     (if (null? alist)
;;         #f
;;         (begin (if (eq? (caar alist) obj) (car alist) (loop obj (cdr alist)))))))
;; (define (assv obj1 alist1)
;;   (let loop ((obj obj1) (alist alist1))
;;     (if (null? alist)
;;         #f
;;         (begin (if (eqv? (caar alist) obj) (car alist) (loop obj (cdr alist)))))))
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
    (if (null? list) #f (if (eqv? obj (car list)) list (loop (cdr list))))))
(define (memq obj list)
  (let loop ((list list))
    (if (null? list) #f (if (eq? obj (car list)) list (loop (cdr list))))))
(define member
  (case-lambda
    ((obj list) (member obj list equal?))
    ((obj list cmp)
      (and (not (null? list))
           (if (cmp obj (car list)) list (member obj (cdr list) cmp))))))
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
(define char-ci=?
  (case-lambda
    ((a b)
      (unless (and (char? a) (char? b)) (error "not chars:" a b))
      (eq? (char-downcase a) (char-downcase b)))
    (rest (comparer (lambda (a b) (char-ci=? a b)) rest))))
(define char-ci>?
  (case-lambda
    ((a b)
      (unless (and (char? a) (char? b)) (error "not chars:" a b))
      (char>? (char-downcase a) (char-downcase b)))
    (rest (comparer (lambda (a b) (char-ci>? a b)) rest))))
(define char-ci<?
  (case-lambda
    ((a b)
      (unless (and (char? a) (char? b)) (error "not chars:" a b))
      (char<? (char-downcase a) (char-downcase b)))
    (rest (comparer (lambda (a b) (char-ci<? a b)) rest))))
(define char-ci>=?
  (case-lambda
    ((a b)
      (unless (and (char? a) (char? b)) (error "not chars:" a b))
      (char>=? (char-downcase a) (char-downcase b)))
    (rest (comparer (lambda (a b) (char-ci>=? a b)) rest))))
(define char-ci<=?
  (case-lambda
    ((a b)
      (unless (and (char? a) (char? b)) (error "not chars:" a b))
      (char<=? (char-downcase a) (char-downcase b)))
    (rest (comparer (lambda (a b) (char-ci<=? a b)) rest))))
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

(define (digit-value ch)
  (unless (char? ch) (error "not a char: " ch))
  (let ((n (char->integer ch)))
    (let lp ((lo 0) (hi (- (vector-length zeros) 1)))
      (and (<= lo hi)
           (let* ((mid (+ lo (quotient (- hi lo) 2)))
                  (mid-zero (char->integer (vector-ref zeros mid))))
             (cond
               ((<= mid-zero n (+ mid-zero 9)) (- n mid-zero))
               ((< n mid-zero) (lp lo (- mid 1)))
               (else (lp (+ mid 1) hi))))))))
;; Zeros taken from chibi
(define zeros
  #(#\0 ;DIGIT ZERO
  ))

(define char-foldcase char-downcase)

;; strings
(define string-copy
  (case-lambda
    ((string) (substring string 0 (string-length string)))
    ((string start) (substring string start (string-length string)))
    ((string start end) (substring string start end))))
(define (str-copy-internal tostr tostart fromstr fromstart fromend)
  (sys:FOREIGN_CALL '(gc_obj "SCM_STR_COPY" (gc_obj int32 gc_obj int32 int32))
                    tostr
                    tostart
                    fromstr
                    fromstart
                    fromend)
  ;; (let loop ((frompos fromstart) (topos tostart))
  ;;   (if (< frompos fromend)
  ;;       (begin
  ;;         (string-set! tostr topos (string-ref fromstr frompos))
  ;;         (loop (+ frompos 1) (+ topos 1)))))
)
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
    ((a b c) (string-append2 a (string-append2 b c)))
    ((a b c d) (string-append2 a (string-append2 b (string-append2 c d))))
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
(define (strcmp eq? f eq lt gt a b)
  (let loop ((pos 0) (rema (string-length a)) (remb (string-length b)))
    (cond
      ((and (= rema 0) (= remb 0)) eq)
      ((= rema 0) lt)
      ((= remb 0) gt)
      ((eq? (string-ref a pos) (string-ref b pos))
        (loop (+ pos 1) (- rema 1) (- remb 1)))
      (else (f (string-ref a pos) (string-ref b pos))))))

(define-syntax define-strcmp
   (syntax-rules (strcmp)
     ((_ name (call args ...))
      (define name
        (case-lambda ((a b) (call args ... a b)) (rest (comparer name rest)))))))

(define-strcmp string<? (strcmp char=? char<? #f #t #f))
(define-strcmp string>? (strcmp char=? char>? #f #f #t))
(define-strcmp string<=? (strcmp char=? char<=? #t #t #f))
(define-strcmp string>=? (strcmp char=? char>=? #t #f #t))
(define-strcmp string-ci<? (strcmp char-ci=? char-ci<? #f #t #f))
(define-strcmp string-ci>? (strcmp char-ci=? char-ci>? #f #f #t))
(define-strcmp string-ci<=? (strcmp char-ci=? char-ci<=? #t #t #f))
(define-strcmp string-ci>=? (strcmp char-ci=? char-ci>=? #t #f #t))
(define-strcmp string-ci=? (strcmp char-ci=? char-ci=? #t #f #f))
(define-strcmp string=? (strcmp char=? char=? #t #f #f))

(define (string-downcase s)
  (let loop ((out '()) (in (string->list s)))
    (cond
      ((null? in) (list->string (reverse out)))
      ((= (char->integer (car in)) 304)
        (loop (cons (integer->char 775) (cons (integer->char 105) out)) (cdr in)))
      (else (loop (cons (char-downcase (car in)) out) (cdr in))))))
(define (string-upcase s)
  (let loop ((out '()) (in (string->list s)))
    (cond
      ((null? in) (list->string (reverse out)))
      ((assv (char->integer (car in)) uppercase-special) =>
         (lambda (x)
           (loop (append (reverse (map integer->char (cadr x))) out) (cdr in))))
      (else (loop (cons (char-upcase (car in)) out) (cdr in))))))
(define uppercase-special
  '((223 (83 83))
    (64256 (70 70))
    (64257 (70 73))
    (64258 (70 76))
    (64259 (70 70 73))
    (64260 (70 70 76))
    (64261 (83 84))
    (64262 (83 84))
    (1415 (1333 1362))
    (64275 (1348 1350))
    (64276 (1348 1333))
    (64277 (1348 1339))
    (64278 (1358 1350))
    (64279 (1348 1341))
    (329 (700 78))
    (912 (921 776 769))
    (944 (933 776 769))
    (496 (74 780))
    (7830 (72 817))
    (7831 (84 776))
    (7832 (87 778))
    (7833 (89 778))
    (7834 (65 702))
    (8016 (933 787))
    (8018 (933 787 768))
    (8020 (933 787 769))
    (8022 (933 787 834))
    (8118 (913 834))
    (8134 (919 834))
    (8146 (921 776 768))
    (8147 (921 776 769))
    (8150 (921 834))
    (8151 (921 776 834))
    (8162 (933 776 768))
    (8163 (933 776 769))
    (8164 (929 787))
    (8166 (933 834))
    (8167 (933 776 834))
    (8182 (937 834))
    (8064 (7944 921))
    (8065 (7945 921))
    (8066 (7946 921))
    (8067 (7947 921))
    (8068 (7948 921))
    (8069 (7949 921))
    (8070 (7950 921))
    (8071 (7951 921))
    (8072 (7944 921))
    (8073 (7945 921))
    (8074 (7946 921))
    (8075 (7947 921))
    (8076 (7948 921))
    (8077 (7949 921))
    (8078 (7950 921))
    (8079 (7951 921))
    (8080 (7976 921))
    (8081 (7977 921))
    (8082 (7978 921))
    (8083 (7979 921))
    (8084 (7980 921))
    (8085 (7981 921))
    (8086 (7982 921))
    (8087 (7983 921))
    (8088 (7976 921))
    (8089 (7977 921))
    (8090 (7978 921))
    (8091 (7979 921))
    (8092 (7980 921))
    (8093 (7981 921))
    (8094 (7982 921))
    (8095 (7983 921))
    (8096 (8040 921))
    (8097 (8041 921))
    (8098 (8042 921))
    (8099 (8043 921))
    (8100 (8044 921))
    (8101 (8045 921))
    (8102 (8046 921))
    (8103 (8047 921))
    (8104 (8040 921))
    (8105 (8041 921))
    (8106 (8042 921))
    (8107 (8043 921))
    (8108 (8044 921))
    (8109 (8045 921))
    (8110 (8046 921))
    (8111 (8047 921))
    (8115 (913 921))
    (8124 (913 921))
    (8131 (919 921))
    (8140 (919 921))
    (8179 (937 921))
    (8188 (937 921))
    (8114 (8122 921))
    (8116 (902 921))
    (8130 (8138 921))
    (8132 (905 921))
    (8178 (8186 921))
    (8180 (911 921))
    (8119 (913 834 921))
    (8135 (919 834 921))
    (8183 (937 834 921))))
(define string-foldcase string-downcase)

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
(define (exact-integer-sqrt s)
  (unless (and (exact? s) (not (negative? s))) (error "not exact" s))
  (if (bignum? s)
      (let ((q&r (sys:FOREIGN_CALL '(gc_obj "bignum_exact_integer_sqrt" (gc_obj)) s)))
        (values (car q&r) (cdr q&r)))
      (if (<= s 1)
          (values s 0)
          (let* ((x0 (quotient s 2)) (x1 (quotient (+ x0 (quotient s x0)) 2)))
            (let loop ((x0 x0) (x1 x1))
              (if (< x1 x0)
                  (loop x1 (quotient (+ x1 (quotient s x1)) 2))
                  (values x0 (- s (* x0 x0)))))))))

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
          ((flonum? num) (sys:FOREIGN_CALL '(string "ftoa_fast" (double)) num))
          ((bignum? num) (sys:FOREIGN_CALL '(string "bignum_string" (gc_obj)) num))
          ((ratnum? num)
            (string-append (number->string (numerator num))
                           "/"
                           (number->string (denominator num))))
          ((compnum? num)
            (string-append (number->string (real-part num))
                           (if (not (or (negative? (imag-part num))
                                       ;(nan? (imag-part num))
                                       ;(infinite? (imag-part num))
                                    ))
                               "+"
                               "")
                           (number->string (imag-part num))
                           "i"))
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

(define *here* (list #f))
;; Due to the way sys:CALLCC works, sys:CALLCC *must* be in its own function. DOH.
(define (call-with-current-continuation-internal thunk) (sys:CALLCC thunk))
(define (call-with-current-continuation thunk)
  (let* ((winds *here*) (res (call-with-current-continuation-internal thunk)))
    (unless (eq? *here* winds) (reroot! winds))
    res))

(define (call/cc thunk) (call-with-current-continuation thunk))


;;;;;; Records
(define (record-set! record index value)
  (unless (record? record) (error "record-set!: not a record" record))
  (sys:STORE record value (+ index 1)))
(define (record-ref record index)
  (unless (record? record) (error "record-ref: not a record" record))
  (sys:LOAD record (+ index 1)))
(define (make-record sz)
  (let ((rec (sys:ALLOC (+ (* 8 (+ 1 sz)) 8) 49))) (sys:STORE rec sz 0) rec))
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

(define make-parameter
  (case-lambda
    ((init) (let ((cell init)) (case-lambda (() cell) ((new) (set! cell new)))))
    ((init converter)
      (let ((cell (converter init)))
        (case-lambda (() cell) ((new) (set! cell (converter new))))))))

;;;;;; Port ops
(define-record-type port (make-port fd input fold-case buf pos len sbuf) port?
  (fd port-fd)
  (input port-input?)
  (fold-case port-fold-case port-fold-case-set!)
  (buf port-buf port-buf-set!)
  (pos port-pos port-pos-set!)
  (len port-len port-len-set!)
  (sbuf port-sbuf port-sbuf-set!))

(define port-buffer-size 4096)
(define (make-input-port fd)
  (make-port fd #t #f (make-string port-buffer-size) 0 0 #f))
(define (make-output-port fd)
  (make-port fd #f #f (make-string port-buffer-size) 0 0 #f))
(define (make-string-input-port str)
  (make-port -1 #t #f str 0 (string-length str) #f))
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
        ((procedure? x)
          (display "#<procedure " port)
          (display (sys:LOAD (sys:LOAD x 1) 1) port)
          (display ">" port))
        ((eq? x #t) (display "#t" port))
        ((eq? x #f) (display "#f" port))
        ((eq? x '()) (display "()" port))
        ((eof-object? x) (display "#<eof>" port))
        ((undefined? x) (display "#<undefined>" port))
        ((port? x) (display "#<port>" port))
        ((record? x)
          (display "#<record" port)
          (let ((typ (record-ref x 0)))
            (when (record? typ) (display " " port) (display (record-type-name typ) port)))
          (display ">" port))
        ((string? x)
          (do ((i 0 (+ i 1)))
               ((= i (string-length x)))
               (write-char (string-ref x i) port)))
        (else (error "Bad type in display: " x)))
      x)))

(define newline
  (case-lambda
    (() (newline (current-output-port)))
    ((port) (display #\newline port))))

(define (input-port? port) (and (port? port) (port-input? port)))
(define (output-port? port) (and (port? port) (not (port-input? port))))

(define current-input-port (make-parameter (make-input-port 0)))
(define current-output-port (make-parameter (make-output-port 1)))
(define current-error-port (make-parameter (make-output-port 2)))

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
    (when (< fd 0)
      (raise-continuable (make-error-object 'file "No such file:" (list file))))
    (make-input-port fd)))
(define (open-output-file file)
  (let ((fd (c-open file 0)))
    (when (< fd 0) (error "open-output-file error:" file))
    (make-output-port fd)))
(define open-binary-output-file open-output-file)
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
(define (clear-port-buffers! port)
  (port-buf-set! port "")
  (port-pos-set! port 0)
  (port-len-set! port 0)
  (port-sbuf-set! port ""))
(define (close-port port)
  (if (>= (port-fd port) 0)
      (begin
        (if (not (port-input? port)) (flush-port-write-buffer port))
        (c-close (port-fd port))
        (record-set! port 1 -2)
        (clear-port-buffers! port))
      (clear-port-buffers! port)))
(define close-output-port close-port)
(define close-input-port close-port)
(define-record-type eof-object-record (make-eof-object) eof-object?)
(define (eof-object) (make-eof-object))
(define (fill-input-port-buffer port)
  (let ((cnt (c-read (port-fd port) (port-buf port) port-buffer-size)))
    (if (> cnt 0)
        (begin (port-pos-set! port 0) (port-len-set! port cnt) #t)
        (begin (port-pos-set! port 0) (port-len-set! port -1) #f))))
(define (read-from-port-buffer port)
  (if (not (port-input? port))
      (error "read-char: not an input port" port)
      (let ((pos (port-pos port)) (len (port-len port)) (buf (port-buf port)))
        (cond
          ((< len 0) (make-eof-object))
          ((< pos len)
            (let ((c (string-ref buf pos))) (port-pos-set! port (+ pos 1)) c))
          (else
            (if (< (port-fd port) 0)
                (begin (port-len-set! port -1) (make-eof-object))
                (if (fill-input-port-buffer port)
                    (read-from-port-buffer port)
                    (make-eof-object))))))))
(define peek-char
  (case-lambda
    (() (peek-char (current-input-port)))
    ((port)
      (if (not (port-input? port))
          (error "peek-char: not an input port" port)
          (let ((pos (port-pos port)) (len (port-len port)) (buf (port-buf port)))
            (cond
              ((< len 0) (make-eof-object))
              ((< pos len) (string-ref buf pos))
              ((< (port-fd port) 0) (port-len-set! port -1) (make-eof-object))
              ((fill-input-port-buffer port) (string-ref buf 0))
              (else (make-eof-object))))))))

(define read-char
  (case-lambda
    (() (read-char (current-input-port)))
    ((port) (read-from-port-buffer port))))
(define (read-line-build chunks total buf start end)
  (let ((len (+ total (- end start))))
    (if (null? chunks)
        (substring buf start end)
        (let ((res (make-string len)))
          (let loop ((chunks (reverse chunks)) (pos 0))
            (if (null? chunks)
                (str-copy-internal res pos buf start end)
                (let ((chunk-len (string-length (car chunks))))
                  (str-copy-internal res pos (car chunks) 0 chunk-len)
                  (loop (cdr chunks) (+ pos chunk-len)))))
          res))))
(define read-line
  (case-lambda
    (() (read-line (current-input-port)))
    ((port)
      (if (not (port-input? port))
          (error "read-line: not an input port" port)
          (let loop ((chunks '()) (total 0))
            (let ((pos (port-pos port)) (len (port-len port)) (buf (port-buf port)))
              (cond
                ((< len 0)
                  (if (= total 0) (make-eof-object) (read-line-build chunks total "" 0 0)))
                ((< pos len)
                  (let scan ((i pos))
                    (cond
                      ((= i len)
                        (port-pos-set! port len)
                        (loop (cons (substring buf pos len) chunks) (+ total (- len pos))))
                      ((char=? (string-ref buf i) #\newline)
                        (port-pos-set! port (+ i 1))
                        (read-line-build chunks total buf pos i))
                      ((char=? (string-ref buf i) #\return)
                        (port-pos-set! port (+ i 1))
                        (let ((res (read-line-build chunks total buf pos i)))
                          (let ((next (peek-char port)))
                            (if (and (char? next) (char=? #\newline next)) (read-char port)))
                          res))
                      (else (scan (+ i 1))))))
                ((< (port-fd port) 0)
                  (port-len-set! port -1)
                  (if (= total 0) (make-eof-object) (read-line-build chunks total "" 0 0)))
                ((fill-input-port-buffer port) (loop chunks total))
                (else
                  (if (= total 0) (make-eof-object) (read-line-build chunks total "" 0 0))))))))))
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
      (let* ((len (- end start)) (str_len (string-length str)))
        (cond
          ((port-sbuf port)
            (port-sbuf-set! port
                            (string-append (port-sbuf port) (substring str start end))))
          ((not (port-input? port))
            (let loop ((pos start) (left len))
              (if (> left 0)
                  (let ((avail (- port-buffer-size (port-len port))))
                    (if (= avail 0)
                        (begin (flush-port-write-buffer port) (loop pos left))
                        (let ((copy (if (< left avail) left avail)))
                          (str-copy-internal (port-buf port) (port-len port) str pos (+ pos copy))
                          (port-len-set! port (+ (port-len port) copy))
                          (loop (+ pos copy) (- left copy))))))))
          (else (error "write-string: not an output port" port)))))))

(define string->list
  (case-lambda
    ((str) (string->list str 0 (string-length str)))
    ((str start) (string->list str start (string-length str)))
    ((str start end)
      (unless (and (fixnum? start) (fixnum? end)) (error "string->list" start))
      (unless (or (< -1 start (string-length str)) (= start end))
        (error "Bad start string->list" start))
      (unless (<= 0 end (string-length str)) (error "Bad end string->list" end))
      (when (> start end) (error "Bad end string->list" end))
      (let string->list-loop ((pos start) (buf '()))
        (if (= pos end)
            (reverse buf)
            (string->list-loop (+ pos 1) (cons (string-ref str pos) buf)))))))

(define string-fill!
  (case-lambda
    ((string fill) (string-fill! string fill 0 (string-length string)))
    ((string fill start) (string-fill! string fill start (string-length string)))
    ((string fill start end)
      (unless (fixnum? start) (error "string->fill!" start))
      (unless (or (< -1 start (string-length string)) (= start end))
        (error "Bad start string->fill!" start))
      (unless (<= 0 end (string-length string)) (error "Bad end string->fill!" end))
      (when (> start end) (error "Bad end string->fill!" end))
      (do ((i start (+ i 1))) ((= i end)) (string-set! string i fill)))))

(define string-copy!
  (case-lambda
    ((to at from) (string-copy! to at from 0 (string-length from)))
    ((to at from start) (string-copy! to at from start (string-length from)))
    ((to at from start end)
      (let ((to-len (string-length to)) (from-len (string-length from)))
        (unless (<= 0 at to-len) (error "to string-copy!" start to-len))
        (unless (and (fixnum? start) (fixnum? end) (fixnum? at))
          (error "fix string-copy!" start))
        (unless (or (< -1 start from-len) (= start end))
          (error "len string-copy!" start from-len))
        (unless (<= 0 end from-len) (error "end string-copy!" end from-len))
        (when (> start end) (error "start end string-copy!" start end))
        (unless (and (or (< -1 at to-len) (= start end)) (<= (+ at (- end start)) to-len))
          (error "bad string-copy! at" at start end))
        (str-copy-internal to at from start end)))))

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

(define (open-input-string str) (make-string-input-port str))
(define (get-input-string port) (port-buf port))
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

(define (current-jiffy) (sys:FOREIGN_CALL '(int64 "scm_current_jiffy" ())))

(define (current-second) (sys:FOREIGN_CALL '(double "scm_current_second" ())))

(define read-buf (make-string 1000))
(define (maybe-lower-case port s)
  (if (port-fold-case port)
      (let ((s (string-copy s)))
        (do ((i 0 (+ i 1)))
             ((= i (string-length s)) s)
             (string-set! s i (char-downcase (string-ref s i)))))
      s))
(define (read-error msg . irritants)
  (raise (make-error-object 'read msg irritants)))

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
          (if (eof-object? c) (read-error "Incomplete escape sequence"))
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
                   (read-error "Invalid hex string escape")
                   (integer->char ch))))
            (else c))))
      (define (read-delimited term)
        (let loop ((res 0) (c (read-char port)))
          (cond
           ((eof-object? c)
            (read-error "incomplete object:" (substring read-buf 0 res) "line: " line))
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
      (define (special-initial? c)
        (memv c '(#\! #\$ #\% #\& #\* #\/ #\: #\< #\= #\> #\? #\@ #\^ #\_ #\~)))
      (define (initial? c) (or (char-alphabetic? c) (special-initial? c)))
      (define (digit? c) (char-numeric? c))
      (define (explicit-sign? c) (memv c '(#\+ #\-)))
      (define (special-subsequent? c)
        (or (explicit-sign? c) (eqv? c #\.) (eqv? c #\@)))
      (define (subsequent? c) (or (initial? c) (digit? c) (special-subsequent? c)))
      (define (sign-subsequent? c)
        (or (initial? c) (explicit-sign? c) (eqv? c #\@)))
      (define (dot-subsequent? c) (or (sign-subsequent? c) (eqv? c #\.)))
      (define (identifier? s)
        (define (all-subsequent? start)
          (let loop ((i start))
            (if (>= i (string-length s))
                #t
                (and (subsequent? (string-ref s i)) (loop (+ i 1))))))
        (let ((n (string-length s)))
          (if (zero? n)
              #f
              (let ((c0 (string-ref s 0)))
                (cond
                 ((initial? c0) (all-subsequent? 1))
                 ((explicit-sign? c0)
                  (cond
                   ((= n 1) #t)
                   ((and (= n 2) (eqv? (string-ref s 1) #\.)) #t)
                   ((sign-subsequent? (string-ref s 1)) (all-subsequent? 2))
                   ((and (>= n 3)
                         (eqv? (string-ref s 1) #\.)
                         (dot-subsequent? (string-ref s 2)))
                    (all-subsequent? 3))
                   (else #f)))
                 ((eqv? c0 #\.)
                  (if (> n 1) (and (dot-subsequent? (string-ref s 1)) (all-subsequent? 2)) #f))
                 (else #f))))))
      (define (read-list)
        (define line-start line)
        (let loop ((res '()))
          (skip-whitespace-and-comments)
          (let ((c (peek-char port)))
            (cond
             ((eof-object? c)
              (read-error "EOF found while parsing list starting on line "
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
                          (read-error "Invalid dotted list")
                          (append (reverse res) fin)))
                    (loop (cons (cond
                                 ((string->number token) => (lambda (num) num))
                                 ((identifier? token) (string->symbol (lower-case token)))
                                 (else (read-error "Invalid symbol" token)))
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
                 ((assoc token named-chars string=?) => cdr)
                 (else (read-error "Error invalid char: " token)))))))
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
                 (read-error "unterminated comment")
                 (loop depth))))))
      (define (read-hash)
        (let ((c (peek-char port)))
          (case c
            ((#\!)
             (read-char port)
             (let ((bang (read-to-delimited)))
               (port-fold-case-set! port
                                    (cond
                                     ((string=? bang "no-fold-case") #f)
                                     ((string=? bang "fold-case") #t)
                                     (else (read-error "Invalid #!:" bang))))))
            ((#\|) (skip-comment))
            ((#\;) (read-char port) (read-one) (read-one))
            ((#\() (read-char port) (list->vector (read-list)))
            ((#\\) (read-char port) (do-read-char))
            ((#\t #\T #\f #\F)
             (let ((v (lower-case (read-to-delimited))))
               (cond
                ((string=? "f" v) #f)
                ((string=? "t" v) #t)
                ((string=? "true" v) #t)
                ((string=? "false" v) #f)
                (else (read-error "Can't parse hash token:" v)))))
            ((#\b #\B #\o #\O #\d #\D #\x #\X #\i #\I #\e #\E)
             (string->number (string-append "#" (read-to-delimited))))
            ((#\u)
             (read-char port)
             (if (not (char=? #\8 (peek-char port)))
                 (read-error "Not a bytevector:" (peek-char port))
                 (read-char port))
             (let ((ls (read-one)))
               (if (not (list? ls)) (read-error "Not a bytevector list:" ls) ls)))
            (else (read-error "Unknown hash: " c)))))
      (define (read-one)
        (skip-whitespace)
        (let ((c (peek-char port)))
          (case (peek-char port)
            ((#\#) (read-char port) (read-hash))
            ((#\() (read-char port) (read-list))
            ((#\)) (read-char port) (read-error "Extra list terminator found"))
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
                ((identifier? token) (string->symbol (maybe-lower-case port token)))
                (else (read-error "Invalid symbol" token))))))))
      (read-one))
    (read2 port))))
;; flonum
;;;;;;;;;
(define (sin d) (sys:FOREIGN_CALL '(double "sin" (double)) (inexact d)))
(define (cos d) (sys:FOREIGN_CALL '(double "cos" (double)) (inexact d)))
(define (asin f)
  (cond
    ((flonum? f) (sys:FOREIGN_CALL '(double "asin" (double)) (inexact f)))
    ((compnum? f)
      (error "asin complex")
      ;(let* ((z (inexact f))) (* 0-1i (log (+ (* 0+1i z) (sqrt (- 1 (expt z 2)))))))
    )
    (else (sys:FOREIGN_CALL '(double "asin" (double)) (inexact f)))))
(define (acos d) (sys:FOREIGN_CALL '(double "acos" (double)) (inexact d)))
(define (sqrt x)
  (cond
    ((compnum? x) (make-polar (sqrt (magnitude x)) (/ (angle x) 2)))
    ((negative? x) (make-rectangular 0.0 (sqrt (abs x))))
    (else (sys:FOREIGN_CALL '(double "sqrt" (double)) (inexact x)))))
(define atan
  (case-lambda
    ((num) (sys:FOREIGN_CALL '(double "atan" (double)) (inexact num)))
    ((num1 num2)
      (if (= num2 0)
          (/ 3.14159 2)
          (let ((res
                   (sys:FOREIGN_CALL '(double "atan" (double)) (/ (inexact num1) (inexact num2)))))
            res
            ;; (if (< num2 0)
            ;;     (if (or (negative? num1) (eqv? -inf.0 (/ 1.0 num1))) ;; hack to check for -0.0
            ;;         (- res 3.14159)
            ;;         (+ res 3.14159))
            ;;     res)
          )))))
(define (tan d) (sys:FOREIGN_CALL '(double "tan" (double)) (inexact d)))
(define (floor-quotient a b)
  (let ((q (/ a b)) (qq (quotient a b)))
    ;; TODO don't use / and quotient both
    (if (and (< q 0) (not (integer? q))) (- qq 1) qq)))
(define (floor/ a b)
  (let* ((div (floor-quotient a b)) (rem (- a (* b div)))) (values div rem)))
(define (truncate/ a b)
  (let* ((div (truncate (quotient a b))) (rem (- a (* b div))))
    (values div rem)))
(define (rationalize x e)
  ;; Implementation by Alan Bawden.
  (define (simplest-rational x y)
    (define (simplest-rational-internal x y)
      ;; Assumes 0 < X < Y
      (let ((fx (floor x)) (fy (floor y)))
        (cond
          ((not (< fx x)) fx)
          ((= fx fy) (+ fx (/ (simplest-rational-internal (/ (- y fy)) (/ (- x fx))))))
          (else (+ 1 fx)))))
    ;; do some juggling to satisfy preconditions
    ;; of simplest-rational-internal.
    (cond
      ((< y x) (simplest-rational y x))
      ((not (< x y))
        (cond
          ((rational? x) x)
          ((and (flonum? x) (not (finite? x)))
            (if (and (flonum? e) (or (nan? e) (= x e))) +nan.0 x))
          (else (assertion-violation 'rationalize "Expected a real number" x e))))
      ((positive? x) (simplest-rational-internal x y))
      ((negative? y) (- (simplest-rational-internal (- y) (- x))))
      (else (if (and (exact? x) (exact? y)) 0 0.0))))
  (simplest-rational (- x e) (+ x e)))
(define (round d)
  (cond
    ((flonum? d)
      (let* ((d (inexact d)) (rounded (sys:FOREIGN_CALL '(double "round" (double)) d)))
        ;; Round to even, towards zero.
        (if (and (= 0.5 (sys:FOREIGN_CALL '(double "fabs" (double)) (- d rounded)))
                 (not (= 0.0 (sys:FOREIGN_CALL '(double "fmod" (double double)) rounded 2.0))))
            (+ rounded (if (> d 0) -1 1))
            rounded)))
    ((ratnum? d)
      (let-values (((q r) (floor/ (numerator d) (denominator d))))
        (let ((half (/ (denominator d) 2)))
          (cond ((> r half) (+ q 1)) ((not (= r half)) q) ((odd? q) (+ 1 q)) (else q)))))
    (else d)))
(define (ceiling x) (sys:FOREIGN_CALL '(double "ceil" (double)) (inexact x)))
(define log
  (case-lambda
    ((num)
      (cond
        ;; TODO fix bc.scm
        ((compnum? num)
          (error "log complex")
          ;;(+ (log (magnitude num)) (* 0+1i (angle num)))
        )
        (else (sys:FOREIGN_CALL '(double "log" (double)) (inexact num)))))
    ((num base) (/ (log num) (log base)))))

;; values

;; This has a custom lowering in bc.scm.
(define (values . vals) (error "BAD VALUES LOWERING"))

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

;;; parameters

(define (command-line) (sys:FOREIGN_CALL '(gc_obj "SCM_COMMAND_LINE" ())))

(define (dynamic-wind before during after)
  (unless (and (procedure? before) (procedure? during) (procedure? after))
    (error "bad dynamic wind proc:" before during after))
  (let ((here *here*))
    (reroot! (cons (cons before after) here))
    (call-with-values during
                      (case-lambda
                        ((value) (reroot! here) value)
                        (values (reroot! here) (apply values results))))))

(define (reroot! there)
  (unless (eq? *here* there)
    (reroot! (cdr there))
    (let ((before (caar there)) (after (cdar there)))
      (set-car! *here* (cons after before))
      (set-cdr! *here* there)
      (set-car! there #f)
      (set-cdr! there '())
      (set! *here* there)
      (before))))

(define (features) '(hawk))

;; Exceptions

(define (with-exception-handler handler thunk)
  (parameterize ((*exception-handlers* (cons handler (*exception-handlers*))))
    (thunk)))
(define (raise-continuable obj)
  (let ((handlers (*exception-handlers*)))
    (parameterize ((*exception-handlers* (cdr handlers))) ((car handlers) obj))))

(define-record-type error-object (make-error-object type msg irritants) error-object?
  (type error-object-type)
  (msg error-object-message)
  (irritants error-object-irritants))

(define (raise obj)
  (let ((handlers (*exception-handlers*)))
    (parameterize ((*exception-handlers* (cdr handlers)))
      ((car handlers) obj)
      (raise (make-error-object 'default-error
                                "Continuing from non-continuable handler"
                                '())))))

(define (default-exception-handler e)
  (let ((eport (current-error-port)))
    (display "ERROR:" eport)
    (write (error-object-type e) eport)
    (newline eport)
    (display (error-object-message e) eport)
    (for-each (lambda (x) (write x eport)) (error-object-irritants e))
    (newline eport)
    (exit -1)))
(define *exception-handlers* (make-parameter `(,default-exception-handler)))

;;;;;;;;;; delay/promise
(define-record-type promise (%make-promise done? value) promise?
  (done? promise-done? promise-done-set!)
  (value promise-value promise-value-set!))

(define (make-promise obj) (if (promise? obj) obj (%make-promise #t obj)))

(define (force promise)
  (unless (promise? promise) (error "force: not a promise" promise))
  (if (promise-done? promise)
      (promise-value promise)
      (let ((promise* ((promise-value promise))))
        (unless (promise-done? promise)
          (promise-done-set! promise (promise-done? promise*))
          (promise-value-set! promise (promise-value promise*)))
        (force promise))))

;;;;;;;; Exceptions
;; Exceptions

(define (with-exception-handler handler thunk)
  (parameterize ((*exception-handlers* (cons handler (*exception-handlers*))))
    (thunk)))

(define (raise-continuable obj)
  (let ((handlers (*exception-handlers*)))
    (parameterize ((*exception-handlers* (cdr handlers))) ((car handlers) obj))))

(define-record-type error-object (make-error-object type msg irritants) error-object?
  (type error-object-type)
  (msg error-object-message)
  (irritants error-object-irritants))

(define (raise obj)
  (let ((handlers (*exception-handlers*)))
    (parameterize ((*exception-handlers* (cdr handlers)))
      ((car handlers) obj)
      (raise (make-error-object 'default-error
                                "Continuing from non-continuable handler"
                                '())))))

(define (error msg . rest)
  (raise (make-error-object 'default-error msg rest)))

(define (file-error? e)
  (and (error-object? e) (eq? 'file (error-object-type e))))

(define (read-error? e)
  (and (error-object? e) (eq? 'read (error-object-type e))))

(define (default-exception-handler e)
  (let ((eport (current-error-port)))
    (display "ERROR:" eport)
    (write (error-object-type e) eport)
    (newline eport)
    (display (error-object-message e) eport)
    (for-each (lambda (x) (write x eport)) (error-object-irritants e))
    (newline eport)
    (exit -1)))

(define *exception-handlers* (make-parameter `(,default-exception-handler)))

