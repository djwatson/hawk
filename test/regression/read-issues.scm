(import (scheme base) (scheme read) (scheme write))

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

(define (read-error-input? input)
  (guard (exn (#t (read-error? exn)))
    (read (open-input-string input))
    #f))

(define (read-input input)
  (guard (exn (#t #f))
    (read (open-input-string input))))

(define (write-read value)
  (guard (exn (#t #f))
    (let ((port (open-output-string)))
      (write value port)
      (read (open-input-string (get-output-string port))))))

;; Symbols written by write must always be readable as the same symbol.
(check (write-read (string->symbol ".5")) (string->symbol ".5"))
(check (write-read (string->symbol "'foo")) (string->symbol "'foo"))
(check (write-read (string->symbol "a[b")) (string->symbol "a[b"))

;; Comments are skipped before list parsing decides whether it has reached ).
(check (read-input "(a #;b)") '(a))
(check (read-input "(a #| hi |#)") '(a))
(check (read-input "(a . b #| hi |#)") '(a . b))

;; Block-comment delimiters consume both characters, including nested pairs.
(check (read-error-input? "#|# 42") #t)
(check (read-input "#| outer #| inner |# outer |# 42") 42)

;; Bytevector elements must be exact integers in the byte range.
(check (read-error-input? "#u8(256)") #t)
(check (read-error-input? "#u8(-1)") #t)
(check (read-input "#u8(0 127 255)") #u8(0 127 255))

;; Delimited tokens grow past the initial one-thousand-character buffer.
(let ((token (make-string 1001 #\a)))
  (check
   (let ((value (guard (exn (#t #f))
                  (read (open-input-string token)))))
     (and (symbol? value) (= (string-length (symbol->string value)) 1001)))
   #t))

;; Dot-prefixed identifiers obey the port's case-fold setting.
(check (read-input "#!no-fold-case (.ABC)")
       (list (string->symbol ".ABC")))

;; Invalid syntax must not be returned as ordinary data.
(check (read-error-input? "#xnope") #t)
(check (read-error-input? "(. a)") #t)
(check (read-error-input? "'") #t)

;; A reference to a completed label aliases its completed value.
(check
 (let ((value (guard (exn (#t #f))
                (read (open-input-string "(#0=(a) #1=#0#)")))))
   (and (pair? value) (eq? (car value) (cadr value))))
 #t)

;; A label defined only in a discarded datum must not leak its placeholder.
(check (let ((value (guard (exn (#t #f))
                     (read (open-input-string "#;#0=(a) #0#")))))
         (procedure? value))
       #f)

;; Only horizontal whitespace may follow a string-continuation backslash.
(check (read-error-input? "\"a\\  garbage\nb\"") #t)

(check (read-input "(#t #f #x10 #\\a #(1) #u8(2))")
       (list #t #f 16 #\a #(1) #u8(2)))
(check (read-input "#| outer #|# still inner |# outer |# 42") 42)
(check (read-error-input? "#|") #t)
(check (read-error-input? "#u8(1.0)") #t)
(check (read-error-input? "#u8(a)") #t)
(check (read-error-input? "#;#0=(a) #0#") #t)
(check (read-input "(#;#0=(a) #0=(b) #0#)") '((b) (b)))
(check (read-input "(#0=#f #1=#0#)") '(#f #f))
(check (read-error-input? "#0=#0#") #t)
(check (read-error-input? "#0=") #t)
(check (read-error-input? "`") #t)
(check (read-error-input? ",@") #t)
(check (read-error-input? "#;") #t)
(check (read-input "\"a\\  \n  b\"") "ab")
(check
 (let ((x (read-input "(#0=(a . #0#) #0#)")))
   (and (pair? x) (eq? (car x) (cadr x)) (eq? (car x) (cdar x))))
 #t)
(check
 (let ((x (read-input "(#0=#(#0#) #0#)")))
   (and (pair? x) (eq? (car x) (cadr x))
        (eq? (car x) (vector-ref (car x) 0))))
 #t)

(newline)
(display "Read regressions: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)

(when (> fail-count 0) (error "Read regressions failed" fail-count))
