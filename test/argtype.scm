(import (scheme base) (scheme write) (scheme inexact) (scheme char) (scheme complex) (scheme eval) (scheme file)
	(scheme inexact) (scheme lazy) (scheme load) (scheme process-context) (scheme read))

(define-syntax test-error
  (syntax-rules ()
    ((_ a)
     (let ((err (guard (cxp (#t #t)) a #f))) 
       (unless err (display "FAIL:") (display 'a) (newline))))))

(define-record-type foo (make-foo) foo?)

(define type-examples
  (list
   #t #\a (list 'test) '() 9739 1.0 1/2
   1000000000000000000000000000000000000000000000000000000
   -1
   1-2i
   (string-copy "test") 'test '#() (vector 'a 'b 'c) (make-foo) (lambda (x) x)))

(define-syntax test-matrix
  (syntax-rules (HERE)
    ((_ a)
     (map (lambda (type) (guard (cxp (#t #t)) (a type) #f)) type-examples))
    ((_ a HERE b)
     (map (lambda (type) (guard (cxp (#t #t)) (a type b) #f)) type-examples))
    ((_ a b HERE)
     (map (lambda (type) (guard (cxp (#t #t)) (a b type) #f)) type-examples))))

(test-error (cons 1))
(test-error (cons))
(test-error (car))
(test-error (car #f))
(test-error (car #\a))
(test-error (car 1.2))
(test-error (car car))
(test-error (car "stest"))
(test-error (car 'car))
(test-error (car #(car)))
(display (test-matrix car)) (newline)
(display (test-matrix + HERE 1)) (newline)
(display (test-matrix / HERE 1)) (newline)
(display (test-matrix abs)) (newline)
(display (test-matrix nan?)) (newline)
(display (test-matrix sin)) (newline)
(display (test-matrix asin)) (newline)
(display (test-matrix inexact)) (newline)
(display (test-matrix call/cc)) (newline)
(display (test-matrix atan)) (newline)
(display (test-matrix exp)) (newline)
(display (test-matrix log)) (newline)
(display (test-matrix finite?)) (newline)
;; Note this only works if the host scheme can modify
;; constants
(display (test-matrix set-car! HERE 1))

(define-syntax slam-test
  (syntax-rules ()
    ((_ func)
     (begin
       (display "Slam test:") (display 'func) (newline) (slam-test-go func)))))

(define debug #f)
(define (slam-test-go func)
  (map (lambda (type)
	 (when debug (display type) (newline))
	 (guard (cxp (#t #t)) (func type) #f)) type-examples)
  (map (lambda (type1)
	 (map (lambda (type2)
		(when debug
		  (display type1) (display " ")
		  (display type2) (newline))
		(guard (cxp (#t #t)) (func type1 type2) #f))
	      type-examples)) type-examples)
  (map (lambda (type1)
	 (map (lambda (type2)
		(map
		 (lambda (type3)
		   (when debug
		   (display type1) (display " ")
		   (display type2) (display " ")
		     (display type3) (newline)
		     )
		   (guard (cxp (#t #t)) (func type1 type2 type3) #f))
		 type-examples))
	      type-examples))
       type-examples))

(define-syntax slam-tests
  (syntax-rules ()
    ((_ test ...)
     (begin
       (begin (display "Test:") (display test) (newline) (flush-output-port)
	      (slam-test test)) ...))))

(slam-test number->string)

(slam-tests
;; base
 reverse length apply append boolean? bytevector? eof-object? complex?  real? rational? integer? exact? inexact? inexact exact char? number? procedure? string? symbol? vector? not pair? list ;
	    ;;make-list			;
	    list-set! list-copy			;
	    zero? negative? positive? odd? even? abs ;
	    boolean=? symbol=? < > <= >= + - / *	;
	    max min modulo gcd lcm			;
	    ;;	    expt			;
	    remainder quotient cdr car set-car! set-cdr! cons eq? eqv? equal? null? ;
	    string<? char=? list-ref list-tail assq member for-each   string->list
	    newline
	    vector-map vector-for-each string-map string-for-each map list->vector
	    ;;make-vector
	    vector-set! vector-ref
	    ;;make-string
	    string-fill! list? equal? vector-length string-length string-set! string-ref
	    vector->list symbol->string string->symbol
	    string->vector
	    vector->string
	    vector-copy
	    vector-fill!
	    vector-copy! vector-append string list->string number->string integer->char char->integer string-copy
	    string-copy! substring string-append vector call/cc values call-with-values dynamic-wind
	    make-parameter flush-output-port peek-char char-ready? 
	    truncate exact-integer-sqrt round rationalize floor ceiling floor/ floor-quotient floor-remainder
	    truncate/ truncate-quotient truncate-remainder imag-part real-part make-rectangular
	    square exact-integer? numerator denominator raise
	    bytevector-length bytevector-copy bytevector-u8-ref bytevector-u8-set! bytevector-copy!
	    bytevector-append utf8->string string->utf8

	    ;; char
	    char-alphabetic? char-ci<=?
		       char-ci<? char-ci=?
		       char-ci>=? char-ci>?
		       char-downcase char-foldcase
		       char-lower-case? char-numeric?
		       char-upcase char-upper-case?
		       char-whitespace? digit-value
		       string-ci<=? string-ci<?
		       string-ci=? string-ci>=?
		       string-ci>? 
		       string-downcase
		       string-foldcase string-upcase

		       ;; complex
		       angle imag-part
	    magnitude make-polar
	    make-rectangular real-part
	    ;; file
	    call-with-input-file call-with-output-file
      delete-file file-exists?
      open-binary-input-file open-binary-output-file
      open-input-file open-output-file
      with-input-from-file with-output-to-file

;;       ;;inexact
      acos asin
	   atan cos
	   exp finite?
	   infinite? log
	   nan? sin
	   sqrt tan

	   ;; lazy
	    force make-promise
	    promise?

	    ;; load
	    load
	    ;; process context
	    command-line
	    ;;emergency-exit
;;		  exit
		  get-environment-variable
		  get-environment-variables

		  ;; read
		  read

		  ;;write
		  write display write-shared write-simple
	    ;; eval
	    environment eval
	    )


