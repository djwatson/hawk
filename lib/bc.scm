;; Bytecode generator for hawk

(import (scheme base) (scheme write) (read) (expand) (scheme process-context) (scheme file) (match)
        (srfi 69) (srfi 1))
(include "opcodes.scm")

(define (cont-pass ir c)
  (match ir
    (#(app ,fun ,sexps ,ann)
      (vector-set! ir 1 (c fun))
      (vector-set! ir 2 (map c sexps)))
    (#(if ,test ,then ,else ,ann)
      (vector-set! ir 1 (c test))
      (vector-set! ir 2 (c then))
      (vector-set! ir 3 (c else)))
    (#(ref ,var ,global ,mutable ,ann) #t)
    (#(set! ,var ,exp ,global? ,ann) (vector-set! ir 2 (c exp)))
    (#(lambda ,vars ,body ,ann) (vector-set! ir 2 (map c body)))
    (#(letrec* ,bindings ,body ,ann) (error "Need letrec conversion"))
    (#(quote ,datum ,ann) #t)
    (#(begin ,sexps ,ann) (vector-set! ir 1 (map c sexps)))
    (#(void ,ann) #t)
    (#(define ,var ,exp ,ann) (vector-set! ir 2 (c exp)))

    ;; From this file:
    (#(primcall ,op ,args ,ann) (vector-set! ir 2 (map c args))))
  ir)

(define primcalls '((+ . ADD) (- . SUB) (< . LT) (= . EQV) (display . WRITE)))
(define (variable-assigned? var) (vector-ref var 2))
(define (variable-name var) (vector-ref var 1))
(define (fix-letrec ir)
  (match ir
    (#(app #(ref #(var ,name #f (core primitive)) #t #f ,ann) ,args ,ann2)
      (guard (assq name primcalls))
      ;;(display "FOUND primcall to ") (display name) (newline)
      `#(primcall ,(cdr (assq name primcalls)) ,(map fix-letrec args) ,ann))
    ;; TODO check not assigned?
    (#(ref ,var ,global ,mutable ,ann)
      (when (variable-assigned? var) (error "var assigned"))
      ir)
    (#(set! ,var ,exp ,global? ,ann) (error "Set! not supported yet"))
    (,else (cont-pass ir fix-letrec))))

;; Functions.
(define (make-fun name)
  ;; code name consts
  (vector '() name (make-hash-table equal?)))
(define (fun-name fun) (vector-ref fun 1))
(define (fun-code fun) (vector-ref fun 0))
(define (fun-consts fun) (vector-ref fun 2))
(define (add-op fun op) (vector-set! fun 0 (cons op (fun-code fun))))

;; Function list as a parameter (mutable)
(define funs (make-parameter #f))
(define (add-fun fun)
  (let ((funs (funs))) (set-car! funs (cons fun (car funs)))))
(define (make-funs-list) (cons '() #f))
(define (get-funs) (car (funs)))

(define (fits-in-int16 value)
  (and (exact? value) (integer? value) (<= -32768 (* 8 value) 32767)))

(define (add-const fun datum)
  (define consts (fun-consts fun))
  (unless (hash-table-exists? consts datum)
    (hash-table-set! consts datum (hash-table-size consts)))
  (hash-table-ref consts datum))

(define (compile ir fun env top tail)
  (define (compile-cont ir) (compile ir fun env top #f))
  (define (finish res) (if tail (begin (add-op fun `(RET ,res))) res))
  (match ir
    (#(lambda ,vars ,body ,ann)
      (let ((new-fun (make-fun "lambda")) (new-env (map cons vars (iota (length vars)))))
        (add-op fun `(LABEL ,top ,(length (get-funs))))
        (add-fun new-fun)
        (add-op new-fun `(FUNC ,(length vars)))
        (map (lambda (ir) (compile ir new-fun new-env (length vars) #t)) body))
      (finish top))
    (#(ref ,var ,global ,mutable ,ann)
      (let ((in-env (assq var env)))
        (finish (if in-env
                    (cdr in-env)
                    (begin (add-op fun `(LOOKUP ,top ,(add-const fun (variable-name var)))) top))))
      ;; TODO possibly needs mov?
    )
    (#(quote ,datum ,ann)
      (if (fits-in-int16 datum)
          (add-op fun `(KSHORT ,top ,(* 8 datum)))
          (add-op fun `(CONST ,top ,(add-const fun datum))))
      (finish top))
    (#(if ,test ,then ,else ,ann)
      (compile test fun env top #f)
      (let* ((offset (length (fun-code fun))) (brop `(IF ,top OFFSET)))
        (add-op fun brop)
        (compile then fun env top tail)
        (set-car! (cddr brop) (- (length (fun-code fun)) offset)))
      (let ((offset (length (fun-code fun))) (jop `(JMP ,top OFFSET)))
        (unless tail (add-op fun jop))
        (let ((res (compile else fun env top tail)))
          (set-car! (cddr jop) (- (length (fun-code fun)) offset))
          res)))
    (#(app ,(compile-cont func) ,args ,ann)
      (let loop ((top (+ top 1)) (args args))
        (unless (null? args)
          (let* ((arg (car args))
                 (res (compile arg fun env top #f))
                 (next (if (= res top) (+ top 1) top)))
            (loop next (cdr args)))))
      (add-op fun `(,(if tail 'CALLT 'CALL) ,top ,(length args)))
      (if tail #f top))
    (#(primcall ,op ,args ,ann)
      (let loop ((atop top) (args args) (argres '()))
        (if (null? args)
            (add-op fun `(,op ,top ,@(reverse argres)))
            (let* ((arg (car args))
                   (res (compile arg fun env atop #f))
                   (next (if (= res atop) (+ atop 1) atop)))
              (loop next (cdr args) (cons res argres)))))
      (finish top))
    (#(define ,var ,(compile-cont exp) ,ann)
      (add-op fun `(DEFINE ,exp ,(add-const fun (variable-name var))))
      #f)
    (#(begin (,sexps ___ ,tail-sexp) ,ann)
      (map compile-cont sexps)
      (compile tail-sexp fun env top tail))
    (,else
      (display "UNKNOWN OP:")
      (display (vector-ref ir 0))
      (newline)
      (cont-pass ir compile-cont))))

(define (read-file port)
  (define r (make-reader port "<stdin>"))
  (let loop ((ann (read r)) (res '()))
    (if (eof-object? ann) (reverse res) (loop (read r) (cons ann res)))))

(define (print-bc fun)
  (display "Compiled fun ")
  (display (fun-name fun))
  (display "\nConsts:\n")
  (for-each (lambda (c) (write c) (newline))
            (hash-table->alist (fun-consts fun)))
  (display "\nBC:\n")
  (for-each (lambda (bc) (display bc) (newline)) (reverse (fun-code fun)))
  (newline))

(define (write-bc fun port)
  ;; TODO: write consts recursively.
  ;; TODO: write fun BC. in 32-bit format: opcode given in opcodes.scm, then a b c as 8-bit fields (0 if unused), or a & D, where a is 8 bit and D is 16 bit.
  ;; LOOKUP, DEFINE, & CONST all need 4-byte OFFSETS backwards as 16-bit values (i.e. 1 means 4 bytes backwards)
)

(define (compile-file file)
  (parameterize ((funs (make-funs-list)))
    (define port (open-input-file file))
    (define out-port (open-output-file (string-append file ".bc")))
    (define forms (read-file port))
    (define expanded (expand-toplevel forms))
    (define fixed `#(begin ,(map fix-letrec expanded) #f))
    (define main (make-fun "main"))
    (compile fixed main '() 0 #t)
    (add-fun main)
    ;; TODO:
    ;; write header
    (for-each (lambda (fun) (write-bc fun port)) (reverse (get-funs)))
    (close-input-port port)
    (close-output-port out-port)))

(display "Compiling:")
(display (cdr (command-line)))
(newline)
(for-each compile-file (cdr (command-line)))

;; IR:
;; passes:
;; DONE fix-letrec - just verify no letrec*
;; DONE assignment-convert - verify no assigned.
;; recover-let: yea probably need or closure convert
;; name-lambdas? TODO
;; closure convert - just ensure no free.
;; DONE inline simple prims.
;; output BC.


