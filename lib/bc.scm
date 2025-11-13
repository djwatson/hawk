;; Bytecode generator for hawk

(import (scheme base) (scheme write) (read) (expand) (scheme process-context) (scheme file) (match))

(define (fix-letrec ir)
  (match ir
    (#(app #(ref #(var ,name #f (core primitive)) #t #f ,ann) ,args ,ann2)
     (display "FOUND primcall to ") (display name) (newline)
     (map fix-letrec args))
    (#(app ,fun ,sexps ,ann)
     (fix-letrec fun)
     (map fix-letrec sexps))
    (#(if ,test ,then ,else ,ann)
     (fix-letrec test)
     (fix-letrec then)
     (fix-letrec else))
    (#(ref ,var ,global ,mutable ,ann) #t)
    (#(set! ,var ,exp ,global? ,ann)
     (unless global?
       (error "Need assignment conversion")))
    (#(lambda ,vars ,body ,ann)
     (map fix-letrec body))
    (#(letrec* ,bindings ,body ,ann)
     (error "Need letrec conversion"))
    (#(quote ,datum ,ann) #t)
    (#(begin ,sexps ,ann)
     (map fix-letrec sexps))
    (#(void ,ann) #t)
    (#(define ,var ,exp ,ann)
     (fix-letrec exp))))

(define (read-file port)
  (define r (make-reader port "<stdin>"))
  (let loop ((ann (read r)) (res '()))
    (if (eof-object? ann) (reverse res) (loop (read r) (cons ann res)))))

(define (compile-file file)
  (define port (open-input-file file))
  (define forms (read-file port))
  (define expanded (expand-toplevel forms))
  (define fixed (map fix-letrec expanded))
  (ir-pp fixed)
  (close-input-port port))

(display "Compiling:") (display (cdr (command-line))) (newline)
(for-each compile-file (cdr (command-line)))

;; IR:
;; passes:
;; fix-letrec - just verify no letrec*
;; assignment-convert - verify no assigned.
;; recover-let: yea probably need or closure convert
;; name-lambdas? TODO
;; closure convert - just ensure no free.
;; inline simple prims.
;; output BC.

