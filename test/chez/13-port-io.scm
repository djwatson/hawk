(import (scheme base) (scheme write))

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

;; String ports
(let ((out (open-output-string)))
  (write "hello" out)
  (check (get-output-string out) "\"hello\""))

(let ((out (open-output-string)))
  (display 42 out)
  (check (get-output-string out) "42"))

(let ((out (open-output-string)))
  (newline out)
  (check (get-output-string out) "\n"))

(let ((in (open-input-string "hello")))
  (check (read-char in) #\h)
  (check (read-char in) #\e)
  (check (read-line in) "llo"))

;; write-shared with shared structure
(let ((out (open-output-string))
      (x (list 1 2 3)))
  (set-cdr! (cddr x) x)
  (write-shared x out)
  (let ((result (get-output-string out)))
    (check (string? result) #t)
    (check (> (string-length result) 0) #t)))

;; write-simple with shared structure
(let ((out (open-output-string))
      (x (list 1 2 3)))
  (write-simple (list x x) out)
  (let ((result (get-output-string out)))
    (check (string? result) #t)))

;; write-shared with shared references
(let ((out (open-output-string))
      (x (list 1 2 3)))
  (write-shared (list x x) out)
  (let ((result (get-output-string out)))
    (check (string? result) #t)))

;; Binary I/O
(let ((out (open-output-bytevector)))
  (write-u8 #x41 out)
  (write-u8 #x42 out)
  (write-u8 #x43 out)
  (check (get-output-bytevector out) #u8(#x41 #x42 #x43)))

(let ((in (open-input-bytevector #u8(#x41 #x42 #x43))))
  (check (read-u8 in) #x41)
  (check (read-u8 in) #x42)
  (check (read-u8 in) #x43)
  (check (eof-object? (read-u8 in)) #t))

;; read-bytevector
(let ((in (open-input-bytevector #u8(1 2 3 4 5))))
  (check (read-bytevector 3 in) #u8(1 2 3))
  (check (read-bytevector 3 in) #u8(4 5)))

;; read-bytevector!
(let ((in (open-input-bytevector #u8(10 20 30)))
      (bv (bytevector 0 0 0)))
  (read-bytevector! bv in 0 3)
  (check bv #u8(10 20 30)))

;; write-bytevector
(let ((out (open-output-bytevector)))
  (write-bytevector #u8(1 2 3 4 5) out)
  (check (get-output-bytevector out) #u8(1 2 3 4 5)))

(let ((out (open-output-bytevector)))
  (write-bytevector #u8(1 2 3 4 5) out 2)
  (check (get-output-bytevector out) #u8(3 4 5)))

(let ((out (open-output-bytevector)))
  (write-bytevector #u8(1 2 3 4 5) out 1 4)
  (check (get-output-bytevector out) #u8(2 3 4)))

;; flush-output-port
(let ((out (open-output-string)))
  (flush-output-port out)
  (check (get-output-string out) ""))

;; Port predicates
(check (textual-port? (open-input-string "abc")) #t)
(check (textual-port? (open-output-string)) #t)
(check (binary-port? (open-input-bytevector #u8(0 1 2))) #t)
(check (binary-port? (open-output-bytevector)) #t)

;; Close port and check state
(let ((in (open-input-string "abc")))
  (close-input-port in)
  (check (input-port-open? in) #f))

(let ((out (open-output-string)))
  (close-output-port out)
  (check (output-port-open? out) #f))

(let ((out (open-output-string)))
  (close-port out)
  (check (output-port-open? out) #f))

;; Reading from closed port should error
(let ((in (open-input-string "abc")))
  (close-input-port in)
  (let ((ok (guard (exn (#t #t)) (read-char in) #f)))
    (check ok #t)))

;; write-string to string port
(let ((out (open-output-string)))
  (write-string "hello" out)
  (check (get-output-string out) "hello"))

(let ((out (open-output-string)))
  (write-string "hello" out 2)
  (check (get-output-string out) "llo"))

(let ((out (open-output-string)))
  (write-string "hello" out 1 4)
  (check (get-output-string out) "ell"))

;; Result
(newline)
(display "Port I/O: ")
(write pass-count)
(display " passed, ")
(write fail-count)
(display " failed")
(newline)
