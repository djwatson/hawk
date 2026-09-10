(import (scheme base) (scheme complex) (scheme file) (scheme inexact)
        (scheme process-context)
        (scheme write))

(define pass-count 0)
(define fail-count 0)

(define-syntax check
  (syntax-rules ()
    ((_ expr expected)
     (let ((result expr))
       (if (equal? result expected)
           (set! pass-count (+ pass-count 1))
           (begin
             (set! fail-count (+ fail-count 1))
             (display "FAIL: ")
             (write 'expr)
             (display " expected ")
             (write expected)
             (display " got ")
             (write result)
             (newline)))))))

(define (raises? thunk)
  (guard (exn (#t #t)) (thunk) #f))

(define-syntax check-values
  (syntax-rules ()
    ((_ expr expected)
     (check (call-with-values (lambda () expr) list) expected))))

;; Constructors must reject negative lengths.
(check (raises? (lambda () (make-vector -1))) #t)
(check (raises? (lambda () (make-bytevector -1))) #t)

;; The integer exponentiation path is only for integer exponents.  In
;; particular, this must not reject exact fractional exponents.
(check (guard (exn (#t #f)) (expt 4 1/2)) 2)
(check (expt 4 -1/2) 1/2)
(check (expt 2 -3) 1/8)

;; A failed read is not EOF.
(check
 (let ((result (guard (exn (#t exn))
                 (call-with-input-file "/tmp"
                   (lambda (port) (read-char port)))
                 #f)))
   (file-error? result))
 #t)

;; The default handler must be able to report a non-error-object.  Calling it
;; directly would terminate this test process through exit; this predicate is
;; the guard required before its error-object accessors are used.
(check (error-object? 'oops) #f)

;; Ordinary vectors remain ordinary vectors when initially packed as flonums.
(let ((v (vector 1.0)))
  (check (guard (exn (#t #f)) (vector-set! v 0 'a) #t) #t)
  (check (vector-ref v 0) 'a))
(let ((v (make-vector 1 1.0)))
  (check (guard (exn (#t #f)) (vector-set! v 0 'a) #t) #t))
(let ((v (list->vector '(1.0))))
  (check (guard (exn (#t #f)) (vector-set! v 0 'a) #t) #t))

;; File wrappers return all callback values, not the close result or first value.
(check (with-output-to-file "/tmp/newhawk-runtime-issues.out"
         (lambda () 42))
       42)
(check-values (call-with-output-file "/tmp/newhawk-runtime-issues.out"
                (lambda (port) (values 1 2)))
              '(1 2))
(check-values (call-with-input-file "/tmp/newhawk-runtime-issues.out"
               (lambda (port) (values 1 2)))
              '(1 2))

(check (floor-remainder -5 2) 1)
(check (exact-integer? (expt 2 100)) #t)
(check (number->string (expt 2 100) 16)
       "10000000000000000000000000")
(check (number->string 10/11 16) "A/B")
(check (number->string (expt 2 400) 2)
       (string-append "1" (make-string 400 #\0)))
(check (number->string (- (expt 10 150)))
       (string-append "-1" (make-string 150 #\0)))
(check (raises? (lambda () (number->string 1 1))) #t)

(check (string->utf8 (string (integer->char 233))) #u8(195 169))
(check (utf8->string #u8(195 169)) (string (integer->char 233)))
(check (raises? (lambda () (utf8->string #u8(192 128)))) #t)
(check (raises? (lambda () (utf8->string #u8(193 191)))) #t)
(check (raises? (lambda () (utf8->string #u8(128 128)))) #t)
(check (raises? (lambda () (utf8->string #u8(195)))) #t)
(check (utf8->string #u8(194 128 195 191))
       (string (integer->char 128) (integer->char 255)))

;; Empty memory ports are already known not to block, and optional port
;; arguments use the current port.
(check (char-ready? (open-input-string "")) #t)
(check (guard (exn (#t #f)) (u8-ready? (open-input-bytevector #u8()))) #t)
(let ((out (open-output-string)))
  (check (guard (exn (#t #f))
          (parameterize ((current-output-port out)) (write-char #\a)))
         #t))
(check (guard (exn (#t #f))
        (parameterize ((current-input-port (open-input-bytevector #u8())))
          (u8-ready?)))
       #t)

(check (assoc 2 '((1 . a) (3 . b)) <) '(3 . b))

;; Boolean exit status must be normalized before crossing the FFI.  Calling
;; (exit #t) is intentionally omitted because it terminates this test process.
;; emergency-exit must also be distinct from exit so it does not flush ports.
(check (eq? emergency-exit exit) #f)

(check (raises? (lambda () (bytevector-u8-set! (bytevector 0) 0 256))) #t)
(check (raises? (lambda () (bytevector 256))) #t)

;; Complex numerical precision and overflow.
(check (< (abs (- (real-part (acos (make-rectangular 0.0 1.0)))
                  1.5707963267948966))
          1e-12)
       #t)
(check (finite? (magnitude 1e200+1e200i)) #t)
(check (magnitude -1e200) 1e200)
(check (magnitude 1e-200) 1e-200)
(check (magnitude -3/4) 3/4)
(call-with-input-file "/tmp/newhawk-runtime-issues.out"
  (lambda (port)
    (read-char port)
    (check (char-ready? port) #t)))
(call-with-port (open-binary-input-file "/tmp/newhawk-runtime-issues.out")
  (lambda (port)
    (read-u8 port)
    (check (u8-ready? port) #t)))

(newline)
(display "Runtime regressions: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
(when (> fail-count 0) (error "Runtime regressions failed" fail-count))
