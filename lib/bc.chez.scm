(import (srfi :1))
(import (srfi :2))
(import (srfi :9))
(import (srfi :69))

(define (features) '(chez))

;; Portable record API expected by headers/expand/all.sld
;; rtd format: #(expand-rtd <name-symbol> <field-list>)
(define (make-record-type name fields)
  (vector 'expand-rtd name fields))

(define (record? x)
  (and (vector? x)
       (> (vector-length x) 0)
       (let ((rtd (vector-ref x 0)))
         (and (vector? rtd)
              (= (vector-length rtd) 3)
              (eq? (vector-ref rtd 0) 'expand-rtd)))))

(define (record-ref rec i)
  (vector-ref rec i))

(define (record-set! rec i v)
  (vector-set! rec i v))

(define (record-set-fast! rec i v)
  (vector-set! rec i v))

(define (record-accessor rtd i)
  (lambda (rec) (record-ref rec i)))

(define (record-constructor rtd . maybe-fields)
  (let* ((all-fields (vector-ref rtd 2))
         (ctor-fields (if (null? maybe-fields) all-fields (car maybe-fields))))
    (lambda args
      (when (not (= (length args) (length ctor-fields)))
        (assertion-violation 'record-constructor "wrong number of constructor args"))
      (let ((rec (make-vector (+ 1 (length all-fields)) #f)))
        (vector-set! rec 0 rtd)
        (for-each
         (lambda (field arg)
           (let loop ((fs all-fields) (idx 1))
             (cond
              ((null? fs)
               (assertion-violation 'record-constructor "unknown field in constructor list"))
              ((eq? field (car fs))
               (vector-set! rec idx arg))
              (else (loop (cdr fs) (+ idx 1))))))
         ctor-fields
         args)
        rec))))

;; Chez script mode may not resolve R7RS libraries through (environment ...).
;; Fall back to the current interaction environment in that case.
(define chez-environment environment)
(define (environment . imports)
  (guard (e (else (interaction-environment)))
    (apply chez-environment imports)))

;; Chez script mode doesn't provide R7RS cond-expand, but expand.scm uses it.
(define-syntax cond-expand
  (syntax-rules (and or not else chez)
    ((cond-expand) (syntax-error "Unfulfilled cond-expand"))
    ((cond-expand (else body ...))
     (begin body ...))
    ((cond-expand ((and) body ...) more-clauses ...)
     (begin body ...))
    ((cond-expand ((and req1 req2 ...) body ...) more-clauses ...)
     (cond-expand
       (req1
         (cond-expand
           ((and req2 ...) body ...)
           more-clauses ...))
       more-clauses ...))
    ((cond-expand ((or) body ...) more-clauses ...)
     (cond-expand more-clauses ...))
    ((cond-expand ((or req1 req2 ...) body ...) more-clauses ...)
     (cond-expand
       (req1
        (begin body ...))
       (else
        (cond-expand
          ((or req2 ...) body ...)
          more-clauses ...))))
    ((cond-expand ((not req) body ...) more-clauses ...)
     (cond-expand
       (req
         (cond-expand more-clauses ...))
       (else body ...)))
    ((cond-expand (chez body ...) more-clauses ...)
     (begin body ...))
    ((cond-expand (feature-id body ...) more-clauses ...)
     (cond-expand more-clauses ...))))

;; Compatibility shims so read.scm (written with R7RS string procedures)
;; can be included directly in Chez.
(define chez-string-copy string-copy)
(define (string-copy s . rest)
  (case (length rest)
    ((0) (chez-string-copy s))
    ((1) (substring s (car rest) (string-length s)))
    ((2) (substring s (car rest) (cadr rest)))
    (else (assertion-violation 'string-copy "wrong number of arguments"))))

(define (string-map f s)
  (list->string (map f (string->list s))))

(define chez-inexact? inexact?)
(define (inexact? x)
  (and (number? x) (chez-inexact? x)))

(define chez-assoc assoc)
(define assoc
  (case-lambda
    ((obj alist) (chez-assoc obj alist))
    ((obj alist cmp)
     (let loop ((xs alist))
       (and (pair? xs)
            (let ((entry (car xs)))
              (if (cmp obj (car entry)) entry (loop (cdr xs)))))))
    (args (assertion-violation 'assoc "wrong number of arguments"))))

(define (error . args)
  (display "ERROR:")
  (for-each (lambda (x)
              (display " ")
              (write x))
            args)
  (newline)
  (exit -1))

(define (write-u8 c p)
  (put-u8 p c))

(define write-bytevector
  (case-lambda
    ((bv) (write-bytevector bv (current-output-port)))
    ((bv port) (put-bytevector port bv))
    ((bv port start) (put-bytevector port bv start (- (bytevector-length bv) start)))
    ((bv port start end) (put-bytevector port bv start (- end start)))))

(define output-bytevector-extractors (make-hash-table eq?))

(define (open-output-bytevector)
  (let-values (((p extract) (open-bytevector-output-port)))
    (hash-table-set! output-bytevector-extractors p extract)
    p))

(define (get-output-bytevector port)
  ((hash-table-ref output-bytevector-extractors
                   port
                   (lambda () (assertion-violation 'get-output-bytevector "invalid port")))))

(define (bytevector-append . bvs)
  (call-with-bytevector-output-port
   (lambda (p)
     (for-each (lambda (bv) (put-bytevector p bv)) bvs))))

(define (open-binary-output-file path)
  (open-file-output-port path (file-options no-fail)))

(define (write-double d p)
  (let ((bv (make-bytevector 8)))
    (bytevector-ieee-double-set! bv 0 d (endianness little))
    (put-bytevector p bv)))

(include "../../scheme-format/read.scm")
(include "../../ariadne/ariadne.scm")
(include "../../expand/syntax-match.scm")
(include "../../expand/lexical-bindings-from-host.scm")
(include "../../expand/builders.scm")
(include "../../expand/syntax.scm")
(include "../../expand/expand.scm")


(define (expander-setup) #t)

(include "match.scm")
(include "bc.scm")

(display "Compiling:")
(display (cdr (command-line)))
(newline)
(for-each (compile-file #f) (cdr (command-line)))
