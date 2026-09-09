(import (scheme base) (scheme write) (scheme read))

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

;; Basic symbols
(check (read (open-input-string "abc")) 'abc)
(check (read (open-input-string "ABC")) 'ABC)

;; Booleans
(check (read (open-input-string "#t")) #t)
(check (read (open-input-string "#f")) #f)
(check (read (open-input-string "#true")) #t)
(check (read (open-input-string "#false")) #f)

;; Numbers
(check (read (open-input-string "42")) 42)
(check (read (open-input-string "-42")) -42)
(check (read (open-input-string "3.14")) 3.14)
(check (read (open-input-string "1/2")) 1/2)

;; Lists
(check (read (open-input-string "()")) '())
(check (read (open-input-string "(1 2 3)")) '(1 2 3))
(check (read (open-input-string "(1 . 2)")) '(1 . 2))
(check (read (open-input-string "(1 . (2))")) '(1 2))

;; Nested lists
(check (read (open-input-string "(a (b c) d)")) '(a (b c) d))

;; Vectors
(check (read (open-input-string "#()")) '#())
(check (read (open-input-string "#(1 2 3)")) '#(1 2 3))

;; Bytevectors
(check (read (open-input-string "#u8()")) #u8())
(check (read (open-input-string "#u8(0 1 2)")) #u8(0 1 2))

;; Quote, quasiquote, unquote
(check (read (open-input-string "'(1 2)")) '(quote (1 2)))
(check (read (open-input-string "`(1 2)")) '(quasiquote (1 2)))
(check (read (open-input-string ",1")) '(unquote 1))
(check (read (open-input-string ",@(1)")) '(unquote-splicing (1)))

;; Characters
(check (char->integer (read (open-input-string "#\\a"))) 97)
(check (char->integer (read (open-input-string "#\\A"))) 65)
(check (char->integer (read (open-input-string "#\\space"))) 32)
(check (char->integer (read (open-input-string "#\\tab"))) 9)
(check (char->integer (read (open-input-string "#\\newline"))) 10)
(check (char->integer (read (open-input-string "#\\return"))) 13)

;; Strings
(check (read (open-input-string "\"hello\"")) "hello")
(check (read (open-input-string "\"\"")) "")
(check (read (open-input-string "\"line1\\nline2\"")) "line1\nline2")
(check (read (open-input-string "\"tab\\there\"")) "tab\there")

;; String escapes
(check (read (open-input-string "\"\\\\\"")) "\\")
(check (read (open-input-string "\"\\\"\"")) "\"")

;; Block comments
(check (read (open-input-string "(a #| block |# b)")) '(a b))
(check (read (open-input-string "(a #| #| nested |# |# b)")) '(a b))

;; Datum comments
(check (read (open-input-string "(a #;expr b)")) '(a b))

;; Line comments
(check (read (open-input-string "(a ; comment\nb)")) '(a b))

;; Circular structure
(check (pair? (read (open-input-string "#0=(1 . #0#)"))) #t)

;; Empty input
(check (eof-object? (read (open-input-string ""))) #t)

;; Multiple reads from same port
(let ((port (open-input-string "(1) (2) (3)")))
  (check (read port) '(1))
  (check (read port) '(2))
  (check (read port) '(3)))

;; Fold-case directive
(check (read (open-input-string "#!fold-case ABC")) 'abc)
(check (read (open-input-string "#!fold-case #!no-fold-case ABC")) 'ABC)

;; Delimiter after boolean (edge case)
(let ((port (open-input-string "#t(1)")))
  (check (read port) #t)
  (check (read port) '(1)))
(let ((port (open-input-string "#true 6 ")))
  (check (read port) #t)
  (check (read port) 6))

;; Result
(newline)
(display "Read syntax: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
