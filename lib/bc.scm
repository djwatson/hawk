;; Bytecode generator for hawk

(import (scheme base)
        (scheme write)
        (read)
        (expand)
        (scheme process-context)
        (scheme file)
        (match)
        (srfi 69)
        (srfi 1)
        (srfi 151)
        ;; gauche
        (rename (only (binary io) write-f64) (write-f64 write-double)))
(include "opcodes.scm")
(include "memory_layout.scm")
(include "fix-letrec.scm")

(define-syntax ->
   (syntax-rules ()
     ((_ arg (command args ...) rest ...) (-> (command arg args ...) rest ...))
     ((_ arg command rest ...) (-> (command arg) rest ...))
     ((_ arg) arg)))

(define (cont-pass ir c)
  ;; (display "Cont pass:")
  ;; (display (ir->sexp ir))
  ;; (newline)
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
    (#(lambda ,vars ,body ,ann) (vector-set! ir 2 (c body)))
    (#(nlambda ,name ,vars ,body ,ann) (vector-set! ir 3 (c body)))
    (#(letrec* ,bindings ,body ,ann)
      (for val bindings (set-car! (cdr val) (c (second val))))
      (vector-set! ir 2 (c body))
      ir)
    (#(let ,bindings ,body ,ann)
      (for val bindings (set-car! (cdr val) (c (second val))))
      (vector-set! ir 2 (c body))
      ir)
    (#(quote ,datum ,ann) #t)
    (#(begin ,sexps ,ann) (vector-set! ir 1 (map c sexps)))
    (#(void ,ann) #t)
    (#(define ,var ,exp ,ann) (vector-set! ir 2 (c exp)))

    ;; From this file:
    (#(primcall ,op ,args ,ann) (vector-set! ir 2 (map c args)))
    (,else (error "Invalid IR:" ir)))
  ir)

(define primcalls '((+ . ADD) (- . SUB) (< . LT) (= . EQV) (display . WRITE)))
(define (variable-assigned? var) (vector-ref var 2))
(define (variable-name var) (vector-ref var 1))
;; Inlines primitives, verifies no assigned vars (TODO)
(define (simple-pass ir)
  (match ir
    (#(app #(ref #(var ,name #f (core primitive)) #t #f ,ann) ,args ,ann2)
      (guard (assq name primcalls))
      ;;(display "FOUND primcall to ") (display name) (newline)
      `#(primcall ,(cdr (assq name primcalls)) ,(map simple-pass args) ,ann))
    ;; TODO check not assigned?
    (#(ref ,var ,global ,mutable ,ann)
      (when (variable-assigned? var) (error "var assigned" var))
      ir)
    (#(set! ,var ,exp ,global? ,ann) (error "Set! not supported yet"))
    (,else (cont-pass ir simple-pass))))

(define (recover-let ir)
  (match ir
    (#(app #(lambda ,args ,body ,lambda-ann) (,params ___) ,app-ann)
      (guard (list? args) (= (length args) (length params)))
      (if (null? params)
          (recover-let body)
          `#(let
             ,(map list args (map recover-let params))
             ,(recover-let body)
             ,lambda-ann)))
    ;; TODO: the rest-args cases
    ;; ((call (lambda (case (,first ___ . ,rest) ,body)) ,params ___)
    ;;   (guard (not (null? rest)) (<= (length first) (length params)))
    ;;   (let ((params (recover-let params))
    ;;         (first-params (take params (length first)))
    ;;         (rest-params (drop params (length first))))
    ;;     `(let
    ;;       (,@(map list first first-params) (,rest (call (lookup list) ,@rest-params)))
    ;;       ,(recover-let body))))
    ;; ((call (lambda (case ,arg ,body)) ,params ___)
    ;;   (guard (symbol? arg))
    ;;   `(let ((,arg (call (lookup list) ,@(map recover-let params))))
    ;;      ,(recover-let body)))
    (,else (cont-pass ir recover-let))))

;; adds name field to lambdas.
(define (name-lambdas ir)
  (match ir
    (#(define ,var #(lambda ,args ,(name-lambdas body) ,lam-ann) ,define-ann)
      `#(define ,var
          #(nlambda ,(symbol->string (vector-ref var 1)) ,args ,body ,lam-ann)
          ,define-ann))
    (#(lambda ,args ,(name-lambdas body) ,lam-ann)
      `#(nlambda "anon" ,args ,(name-lambdas body) ,lam-ann))
    ;; TODO more names.
    ;; ((set! ,var (lambda ,(name-lambdas cases) ___))
    ;;  `(set! ,var (nlambda ,(symbol->string var) ,cases ___)))
    ;; ((fix ,vars (lambda ,(name-lambdas cases) ___) ___ ,(name-lambdas fix-body))
    ;;  (let ((names (map symbol->string vars)))
    ;;    `(fix ,vars (nlambda ,names ,cases ___) ___ ,fix-body)))
    (,else (cont-pass ir name-lambdas))))

;; Add  fix (i.e. letrec*) to all.
(define (fix-all ir)
  ;; (display "fix-all:")
  ;; (display ir)
  ;; (newline)
  (match ir
    ;; Don't need to run on already-fixed things.
    (#(letrec* ((,vars #(nlambda ,name ,args ,(fix-all body) ,lam-ann) ,unused-ann) ___)
        ,(fix-all letrec-body)
        ,letrec-ann)
      (let ((bindings
               (omap (var name args body lam-ann unused-ann)
                     (vars name args body lam-ann unused-ann)
                     `(,var #(nlambda ,name ,args ,body ,lam-ann) ,unused-ann))))
        `#(letrec* ,bindings ,letrec-body ,letrec-ann)))
    (#(nlambda ,name ,args ,(fix-all body) ,ann)
      (let ((tmp (vector 'var (string->symbol name) #f #f)))
        `#(letrec* ((,tmp #(nlambda ,name ,args ,body ,ann) #f))
            #(ref ,tmp #f #f #f)
            #f)))
    (,else (cont-pass ir fix-all))))

(define (uncover-free ir)
  (let uncover-free ((ir ir) (bindings '()) (fv-info (make-hash-table eq?)))
    (define (pass ir)
      (match ir
        (#(ref ,var ,unused ,unused2 ,unused3)
          (when (memq var bindings) (hash-table-set! fv-info var #t))
          ir)
        (#(let ((,vars ,(pass inits)) ___) ,body ,ann)
          (let ((new-body (uncover-free body (append vars bindings) fv-info)))
            (for key vars (hash-table-delete! fv-info key))
            `#(let ,(omap (vars inits) (vars inits) `(,vars ,inits)) ,new-body ,ann)))
        ;; TODO the same as let?
        ;; ((loop ,vars ,name ,body ,(pass args) ___)
        ;;   (let ((new-body (uncover-free body (append vars bindings) fv-info)))
        ;;     (for key vars (hash-table-delete! fv-info key))
        ;;     `(loop ,vars ,name ,new-body ,args ___)))
        (#(letrec* ((,vars #(nlambda ,name ,args ,lbody ,lann) ,lrann) ___) ,body ,ann)
          (let* ((new-env (append vars bindings))
                 (infos (omap _ vars (make-hash-table eq?)))
                 (new-lbodies
                    (omap (args lbody info)
                          (args lbody infos) ;; For each lambda
                          (uncover-free lbody (append (to-proper args) new-env) info)))
                 (new-body (uncover-free body new-env fv-info))
                 (free-vars
                    (omap (args table)
                          (args infos) ;; for each lambda
                          (for key (to-proper args) (hash-table-delete! table key))
                          (hash-table-keys table))))

            (for table infos (hash-table-merge! fv-info table))
            (for key vars (hash-table-delete! fv-info key))
            (let ((bindings
                     (omap (var name free-vars args new-lbody lann lrann)
                           (vars name free-vars args new-lbodies lann lrann)
                           `(,var #(nlambda ,name (free ,@free-vars) ,args ,new-lbody ,lann) ,lrann))))
              `#(letrec* ,bindings ,new-body ,ann))))
        (,else (cont-pass ir pass))))
    (pass ir)))

(define (convert-closures ir)
  (let convert-closures ((ir ir) (replace '()))
    (define (convert ir)
      (match ir
        (#(ref ,var ,unused ,unused2 ,unused3)
          (cond ((assq var replace) => (lambda (newvar) (cdr newvar))) (else ir)))
        (#(letrec* ((,vars #(nlambda ,name (free ,free ___) ,args ,lbody ,lann) ,lrann) ___)
            ,(convert body)
            ,ann)
          (let* ((var-labels
                    (map (lambda (n)
                           (string->symbol (string-append (symbol->string (vector-ref n 1))
                                                          "-label")))
                         vars))
                 (closure-vars (omap _ vars `#(var clo #f #f)))
                 (new-lbody
                    (omap (clo free body)
                          (closure-vars free lbody) ;; for each lambda
                          (convert-closures body
                                            (omap (fv num)
                                                  (free (iota (length free) 1))
                                                  `(,fv .
                                                        #(primcall closure-ref
                                                                   (#(ref ,clo #f #t #f)
                                                                    #(quote ,num #f))
                                                                   #f))))))
                 (new-args
                    (omap (clo-var case-args)
                          (closure-vars args) ;; for each lambda
                          `(,clo-var . ,case-args)))
                 (fvars-cnt (map length free))
                 (new-label-bindings
                    (omap (label name args lbody lann lrann)
                          (var-labels name new-args new-lbody lann lrann)
                          `(,label #(nlambda ,name ,args ,lbody ,lann) ,lrann)))
                 (new-closure-bindings
                    (omap (var fvar-cnt label)
                          (vars fvars-cnt var-labels)
                          `(,var #(closure ,fvar-cnt #(label ,label))))))
            `#(letrec* ,new-label-bindings
                #(let
                  ,new-closure-bindings
                  #(begin
                     (,@(apply append
                               (omap (clo fvars)
                                     (vars free)
                                     (omap (fv num)
                                           (fvars (iota (length fvars) 1))
                                           `#(primcall closure-set!
                                                       (#(ref ,clo #f #t #f)
                                                        #(quote ,num #f)
                                                        ,(convert `#(ref ,fv #f #t #f)))
                                                       #f))))
                      ,body)
                     #f)
                  #f)
                #f)))
        (,else (cont-pass ir convert))))
    (convert ir)))

;; The bytecode does not support raw comparison operators, only
;; branching versions.  Replace comparison ops with branching +
;; comparison if in an 'if' test position, otherwise replace with a
;; branch + true/false constant result.
(define jcmp '((LT . JLT) (EQV . JEQV)))
(define (lower-comparisons ir)
  (match ir
    ;; If it's already behind a if test, it's okay
    (#(if #(primcall ,test ,args ,ann1) ,then ,else ,ann2)
      (guard (assq test jcmp))
      `#(if #(primcall ,test ,(map lower-comparisons args) ,ann1)
            ,(lower-comparisons then)
            ,(lower-comparisons else)
            ,ann1))
    ;; Otherwise wrap it in if branch.
    (#(primcall ,test ,args ,ann1)
      (guard (assq test jcmp))
      `#(if #(primcall ,test ,(map lower-comparisons args) ,ann1)
            #(quote #t ,ann1)
            #(quote #f ,ann1)
            ,ann1))
    (,else (cont-pass ir lower-comparisons))))

;; Functions.
(define-record-type fun (make-fun-record code name consts const-list) fun?
  (code fun-code set-fun-code!)
  (name fun-name)
  (consts fun-consts)
  (const-list fun-consts-list set-fun-consts-list!))

(define (make-fun name)
  (make-fun-record '() name (make-hash-table equal?) '()))

(define (add-op fun op) (set-fun-code! fun (cons op (fun-code fun))))

;; Function list as a parameter (mutable)
(define funs (make-parameter #f))
(define (add-fun fun)
  (let ((funs (funs))) (set-car! funs (cons fun (car funs)))))
(define (make-funs-list) (cons '() #f))
(define (get-funs) (car (funs)))

(define (fits-in-int16 value)
  (and (exact? value) (integer? value) (<= -32768 (* 8 value) 32767)))

(define (fits-in-int64 value)
  (and (exact? value)
       (integer? value)
       (<= (- (expt 2 63)) value (- (expt 2 63) 1))))

(define (add-const fun datum)
  (define consts (fun-consts fun))
  (unless (hash-table-exists? consts datum)
    (hash-table-set! consts datum (hash-table-size consts))
    (set-fun-consts-list! fun (cons datum (fun-consts-list fun))))
  (hash-table-ref consts datum))

(define (make-const-order) (cons '() #f))
(define (const-order-add! order c) (set-car! order (cons c (car order))))
(define (const-order-list order) (car order))

(define (ensure-const-id datum consts const-table const-order)
  (unless (hash-table-exists? consts datum)
    (hash-table-set! consts datum datum))
  (let ((canonical (hash-table-ref consts datum)))
    (if (hash-table-exists? const-table canonical)
        (hash-table-ref const-table canonical)
        (let ((idx (hash-table-size const-table)))
          (hash-table-set! const-table canonical idx)
          (const-order-add! const-order canonical)
          (register-const-deps canonical consts const-table const-order)
          idx))))

(define (register-const-deps datum consts const-table const-order)
  (cond
    ((symbol? datum)
      (ensure-const-id (symbol->string datum) consts const-table const-order))
    ((const-closure? datum)
      (ensure-const-id (const-closure-fun datum) consts const-table const-order))
    ((fun? datum)
      (ensure-const-id (fun-name datum) consts const-table const-order)
      (for-each (lambda (const) (ensure-const-id const consts const-table const-order))
                (reverse (fun-consts-list datum))))
    (else #f)))

(define (const-id-of datum consts const-table)
  (unless (hash-table-exists? consts datum)
    (error "Unknown constant during emission:" datum))
  (let ((canonical (hash-table-ref consts datum)))
    (unless (hash-table-exists? const-table canonical)
      (error "Missing ID for constant:" datum))
    (hash-table-ref const-table canonical)))

(define-record-type const-closure (make-const-closure fun) const-closure?
  (fun const-closure-fun))

(define (compile ir fun env top tail)
  (define (compile-cont ir) (compile ir fun env top #f))
  (define (finish res) (if tail (begin (add-op fun `(RET ,res))) res))
  (match ir
    (#(letrec* ((,vars ,inits ,ann1) ___) ,body ,ann2)
      (let* ((label-funs
                (omap init
                      inits
                      (match init
                        (#(nlambda ,name ,args ,lbody ,lann) (make-fun name))
                        (,else (error "Invalid letrec* init in compile:" init)))))
             (label-env (map cons vars label-funs)))
        (for-each (lambda (func init var)
                    (match init
                      (#(nlambda ,name ,args ,lbody ,lann)
                        (let* ((arg-list (to-proper args))
                               (arg-env (map cons arg-list (iota (length arg-list) 0)))
                               (new-env (append arg-env label-env env)))
                          (add-fun func)
                          (add-op func `(FUNC ,(length arg-list)))
                          (compile lbody func new-env (length arg-list) #t)))
                      (,else (error "Invalid letrec* init in compile:" init))))
                  label-funs
                  inits
                  vars)
        (compile body fun (append label-env env) top tail)))
    (#(closure ,cnt #(label ,label))
      (cond
        ((assq label env) =>
           (lambda (entry)
             (add-op fun `(CONST ,top ,(add-const fun (cdr entry))))
             (add-op fun `(CLOSURE ,top ,cnt))
             (finish top)))
        (else (error "Unknown label in closure:" label))))
    (#(let ((,vars ,inits) ___) ,body ,ann)
      (let ((regs (iota (length vars) top)))
        (for (init reg) (inits regs)
          (let ((res (compile init fun env reg #f)))
            (unless (= res reg) (add-op fun `(MOV ,reg ,res)))))
        (compile body
                 fun
                 (append (map cons vars regs) env)
                 (+ top (length vars))
                 tail)))
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
      (match test
        (#(primcall ,op ,args ,ann)
          (guard (assq op jcmp))
          (compile `#(primcall ,(cdr (assq op jcmp)) ,args ,ann) fun env top #f))
        (,else (compile test fun env top #f) (add-op fun (list 'IF top top))))
      (let* ((offset (length (fun-code fun))) (brop (list 'JMP top 0)))
        (add-op fun brop)
        (compile then fun env top tail)
        (set-car! (cddr brop) (- (length (fun-code fun)) offset)))
      (let ((offset (length (fun-code fun))) (jop (list 'JMP top 0)))
        (unless tail (add-op fun jop))
        (let ((res (compile else fun env top tail)))
          (set-car! (cddr jop) (- (length (fun-code fun)) offset))
          res)))
    (#(app ,func ,args ,ann)
      ;; Leave room for func + pointer.
      (let loop ((top (+ top 1)) (args (cons func args)))
        (unless (null? args)
          (let* ((arg (car args)) (res (compile arg fun env top #f)))
            (unless (= res top) (add-op fun `(MOV ,top ,res)))
            (loop (+ top 1) (cdr args)))))
      (add-op fun `(CLOSURE_GET ,top ,(+ top 1) 0))
      (add-op fun `(,(if tail 'LCALLT 'LCALL) ,top ,(+ 2 (length args))))
      (if tail #f top))
    (#(primcall closure-ref (,clo ,slot) ,ann)
      (let ((slot-num
               (match slot
                 (#(quote ,num ,ann2) num)
                 (,else (error "Invalid closure-ref slot:" slot)))))
        (let ((clo-res (compile clo fun env top #f)))
          (add-op fun `(CLOSURE_GET ,top ,clo-res ,slot-num))
          (finish top))))
    (#(primcall closure-set! (,clo ,slot ,val) ,ann)
      (let ((slot-num
               (match slot
                 (#(quote ,num ,ann2) num)
                 (,else (error "Invalid closure-set! slot:" slot)))))
        (let* ((val-res (compile val fun env top #f))
               (clo-res (compile clo fun env (+ top 1) #f)))
          (add-op fun `(CLOSURE_SET ,val-res ,clo-res ,slot-num))
          (finish top))))
    (#(primcall ,op ,args ,ann)
      (let loop ((atop top) (args args) (argres '()))
        (if (null? args)
            (let ((argres (reverse argres)))
              (add-op fun
                      `(,op ,@(if (eq? op 'STORE) '() (list top)) ,@argres)))
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
    (#(void ,ann) (add-op fun `(KSHORT ,top ,undefined-tag)) (finish top))
    (,else (error "UNKNOWN OP:" ir))))

(define (read-file port)
  (define r (make-reader port "<stdin>"))
  (let loop ((ann (read r)) (res '()))
    (if (eof-object? ann) (reverse res) (loop (read r) (cons ann res)))))

(define (print-bc fun)
  (display "Compiled fun ")
  (display (fun-name fun))
  (display "\nConsts:\n")
  (for-each (lambda (c) (write c) (newline)) (reverse (fun-consts-list fun)))
  (display "\nBC:\n")
  (for-each (lambda (bc) (display bc) (newline)) (reverse (fun-code fun)))
  (newline))

(define (mask-byte b) (modulo b 256))

(define (write-u16 v p)
  (write-u8 (mask-byte v) p)
  (write-u8 (mask-byte (arithmetic-shift v -8)) p))

(define (zigzag-encode v)
  (let ((shifted (arithmetic-shift (abs v) 1)))
    (if (negative? v) (+ shifted 1) shifted)))

;; prefix varint
;;    7 bits -> 0xxxxxxx
;;    14 bits -> 10xxxxxx xxxxxxxx
;;    ...
;;    35 bits -> 11110xxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
;;    ...
;;    128 bits -> 11111111 11111111 xxxxxxxx xxxxxxxx ... xxxxxxxx
(define (write-pvarint-u64 v p)
  (define (write-bytes v cnt p)
    (do ((i 0 (+ i 1)) (v v (arithmetic-shift v -8)))
         ((= i cnt))
         (write-u8 (mask-byte v) p)))
  (let loop ((i 1) (shift 7))
    (if (= i 9)
        (begin (write-u8 0 p) (write-bytes v 8 p))
        (if (< v (arithmetic-shift 1 shift)) ;; fixed?
            (write-bytes (+ (arithmetic-shift v i) (arithmetic-shift 1 (- i 1))) i p)
            (loop (+ i 1) (+ shift 7))))))

(define (tag-ptr ptr tag) (+ (* ptr 8) tag))
(define (fixnum? c) (and (integer? c) (exact? c) (fits-in-int64 c)))
(define (flonum? c) (and (inexact? c) (real? c)))
(define (write-const p c consts const-table)
  (cond
    ((symbol? c)
      (let ((name-id (const-id-of (symbol->string c) consts const-table)))
        (write-pvarint-u64 symbol-tag p)
        (write-pvarint-u64 (tag-ptr name-id ptr-tag) p)))
    ((flonum? c) (write-pvarint-u64 flonum-tag p) (write-double c p))
    ((fixnum? c) (write-pvarint-u64 (zigzag-encode (tag-ptr c fixnum-tag)) p))
    ;; ((char? c))
    ;; ((boolean? c))
    ;; ((null? c))
    ((string? c)
      (write-pvarint-u64 string-tag p)
      (write-pvarint-u64 (tag-ptr (string-length c) fixnum-tag) p)
      (string-for-each (lambda (c) (write-u8 (char->integer c) p)) c))
    ;; ((vector? c))
    ;; ((pair? c))
    ((fun? c) (write-bc c p consts const-table))
    ((const-closure? c)
      (write-pvarint-u64 closure-tag p)
      (let ((fun-id (const-id-of (const-closure-fun c) consts const-table)))
        (write-pvarint-u64 (tag-ptr fun-id closure-tag) p)))
    ((boolean? c)
      (if c (write-pvarint-u64 true-rep p) (write-pvarint-u64 false-rep p)))
    ((null? c) (write-pvarint-u64 nil-tag p))
    (else (error "Unknown const in write-const:" c))))

(define (write-bc fun port consts const-table)
  (define code (reverse (fun-code fun)))
  (define const-count (hash-table-size (fun-consts fun)))
  (write-pvarint-u64 func-tag port)
  (write-const port (fun-name fun) consts const-table)
  (write-pvarint-u64 const-count port)
  (write-pvarint-u64 (length code) port)
  (for-each (lambda (const)
              (write-pvarint-u64 (const-id-of const consts const-table) port))
            (reverse (fun-consts-list fun)))
  (for-each (lambda (c idx)
              (define op (first c))
              (unless (assq op opcodes) (error "Unknown opcode:" op))
              (write-u8 (cdr (assq op opcodes)) port) ;; eval? or some easier way?
              (write-u8 (second c) port)
              (cond
                ((memq op '(LOOKUP CONST DEFINE))
                  (let* ((const-offset (- (hash-table-size (fun-consts fun)) (third c)))
                         (code-offset (+ idx (* 2 const-offset))))
                    (unless (fits-in-int16 code-offset) (error "Bad const offset"))
                    (write-u16 code-offset port)))
                ((memq op ops_abc) (write-u8 (third c) port) (write-u8 (fourth c) port))
                ((memq op ops_ad) (write-u16 (third c) port))
                ((memq op ops_a) (write-u16 0 port))
                (else (error "Unknown op type:" c))))
            code
            (iota (length code))))

(define (compile-file file)
  (define (debug-print item) (display (ir->sexp item)) (newline) item)
  (define (run-expansion forms) `#(begin ,(expand-toplevel forms) #f))
  (parameterize ((funs (make-funs-list)))
    (define port (open-input-file file))
    (define out (open-output-file (string-append file ".bc")))
    (define lowered
      (-> port
          read-file
          run-expansion
          debug-print
          simple-pass
          fix-letrec
          lower-comparisons
          recover-let
          name-lambdas
          fix-all
          debug-print
          uncover-free
          convert-closures))
    (define main (make-fun "main"))
    (define consts (make-hash-table equal?)) ;; de-duplication table.
    (define const-table (make-hash-table eq?)) ;; Result ordering.  ALSO sorts out recursive structures.
    (define const-order (make-const-order))
    (close-input-port port)
    ;; Actual compilation step.
    (compile lowered main '() 0 #f)
    (add-op main `(HALT 0))
    (add-fun main)

    ;; Emit to file.
    ;; Magic
    (string-for-each (lambda (c) (write-u8 (char->integer c) out)) "HAWK")
    ;; version
    (write-pvarint-u64 0 out)
    ;; TODO reverse funs?
    (let ((funs (get-funs)))
      (for-each (lambda (fun) (ensure-const-id fun consts const-table const-order))
                funs)
      (let* ((const-list (const-order-list const-order))
             (const-count (length const-list)))
        (write-pvarint-u64 const-count out)
        (for-each (lambda (const) (write-const out const consts const-table))
                  const-list)
        (for-each print-bc funs)))
    (close-output-port out)))

(display "Compiling:")
(display (cdr (command-line)))
(newline)
(for-each compile-file (cdr (command-line)))

;; IR:
;; passes:
;; DONE assignment-convert - verify no assigned.
;; DONE recover-let: yea probably need or closure convert
;; name-lambdas? TODO
;; closure convert - just ensure no free.
;; DONE inline simple prims.
;; output BC.
#|
static size_t pvarint_len(const uint8_t p) {
  return 1 + __builtin_ctz(p | 0x100);
}

static uint64_t read_pvarint(FILE *fptr) {
  uint64_t res;
  if (1 != fread(&res, 1, 1, fptr)) {
    read_error();
  }
  uint8_t len = pvarint_len(res);
  if (len < 9) {
    size_t unused = 64 - 8 * len;
    if (len - 1 != fread(((uint8_t *)&res) + 1, 1, len - 1, fptr)) {
      read_error();
    }
    return res << unused >> (unused + len);
  }
  if (8 != fread(&res, 1, 8, fptr)) {
    read_error();
  }
  return res;
}
|#
