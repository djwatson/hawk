;; Bytecode generator for hawk

(import (scheme base) (scheme write) (read) (expand) (scheme process-context) (scheme file) (match)
        (srfi 69) (srfi 1) (srfi 151))
(include "opcodes.scm")
(include "memory_layout.scm")

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
    (#(lambda ,vars ,body ,ann)
      (let* ((new-fun (make-fun "lambda"))
             (clo (make-const-closure new-fun))
             ;; TODO: figure out if we really need closure offset
             (closure-offset 1)
             (new-env (map cons vars (iota (length vars) closure-offset))))
        (add-op fun `(CONST ,top ,(add-const fun clo)))
        (add-fun new-fun)
        (add-op new-fun `(FUNC ,(+ closure-offset (length vars))))
        (map (lambda (ir) (compile ir new-fun new-env (+ closure-offset (length vars)) #t))
             body))
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
    (#(app ,func ,args ,ann)
      ;; Leave room for func + pointer.
      (let loop ((top (+ top 2)) (args args))
        (unless (null? args)
          (let* ((arg (car args)) (res (compile arg fun env top #f)))
            (unless (= res top) (add-op fun `(MOV ,top ,res)))
            (loop (+ top 1) (cdr args)))))
      (compile func fun env (+ top 1) #f)
      (add-op fun `(CLOSURE_GET ,top ,(+ top 1) 0))
      (add-op fun `(,(if tail 'LCALLT 'LCALL) ,top ,(+ 2 (length args))))
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
  (for-each (lambda (c) (write c) (newline)) (reverse (fun-consts-list fun)))
  (display "\nBC:\n")
  (for-each (lambda (bc) (display bc) (newline)) (reverse (fun-code fun)))
  (newline))

(define (mask-byte b) (modulo b 256))
(define (write-u32 v p)
  (write-u8 (mask-byte v) p)
  (write-u8 (mask-byte (arithmetic-shift v -8)) p)
  (write-u8 (mask-byte (arithmetic-shift v -16)) p)
  (write-u8 (mask-byte (arithmetic-shift v -24)) p))

(define (write-u64 v p)
  (write-u8 (mask-byte v) p)
  (write-u8 (mask-byte (arithmetic-shift v -8)) p)
  (write-u8 (mask-byte (arithmetic-shift v -16)) p)
  (write-u8 (mask-byte (arithmetic-shift v -24)) p)
  (write-u8 (mask-byte (arithmetic-shift v -32)) p)
  (write-u8 (mask-byte (arithmetic-shift v -40)) p)
  (write-u8 (mask-byte (arithmetic-shift v -48)) p)
  (write-u8 (mask-byte (arithmetic-shift v -56)) p))

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
(define (write-const p c consts const-table)
  (cond
    ((symbol? c)
      (let ((name-id (const-id-of (symbol->string c) consts const-table)))
        (write-pvarint-u64 symbol-tag p)
        (write-pvarint-u64 (tag-ptr name-id ptr-tag) p)))
    ;; ((flonum? c))
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
    (else (error "Unknown const in write-const:" c))))

(define (write-bc fun port consts const-table)
  (define code (reverse (fun-code fun)))
  (define const-count (hash-table-size (fun-consts fun)))
  (write-pvarint-u64 func-tag port)
  (write-pvarint-u64 const-count port)
  (write-pvarint-u64 (length code) port)
  (for-each (lambda (const) (write-u64 (const-id-of const consts const-table) port))
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
  (parameterize ((funs (make-funs-list)))
    (define port (open-input-file file))
    (define out (open-output-file (string-append file ".bc")))
    (define forms (read-file port))
    (define expanded (expand-toplevel forms))
    (define unused (display (map ir->sexp expanded)))
    (define fixed `#(begin ,(map fix-letrec expanded) #f))
    (define main (make-fun "main"))
    (define consts (make-hash-table equal?)) ;; de-duplication table.
    (define const-table (make-hash-table eq?)) ;; Result ordering.  ALSO sorts out recursive structures.
    (define const-order (make-const-order))
    (close-input-port port)
    ;; Actual compilation step.
    (compile fixed main '() 0 #f)
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
;; DONE fix-letrec - just verify no letrec*
;; DONE assignment-convert - verify no assigned.
;; recover-let: yea probably need or closure convert
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
